package cn.ctyun.oos.iam.test.oosaccesscontrol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Principal;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import cn.ctyun.oos.utils.HbaseUtils;
import cn.ctyun.oos.utils.api.IAMAPITestUtils;
import cn.ctyun.oos.utils.api.OOSAPITestUtils;
import cn.ctyun.oos.utils.env.CleanTable;
import common.tuple.Pair;

public class OOSBucketPolicyAccessTest {
	public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
	public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
	public static final String regionName="cd";

    public static final int jettyHttpPort=80;
    public static final int jettyHttpsPort=8444;
    
    public static final String httpOrHttps="http";
    public static final int jettyport=jettyHttpPort;
    
    public static final String signVersion="V4";
    
    
    public static final String bucketName="yx-bucket-1";
    public static final String bucketName1="yx-bucket-2";
    
    //用于资源匹配
    public static final String bucketName2="yx-bucket-3";
    public static final String bucketName4="yx-bucket-4";
	
    //一个元数据域，多个数据域
    public static final String ownerName="root_user1@test.com";
	public static final String accessKey="userak1";
	public static final String secretKey="usersk1";
	public static final OwnerMeta owner=new OwnerMeta(ownerName);
	public static final String accountId="3fdmxmc3pqvmp";
	static String dataregion1="yxregion1";
	static String dataregion2="yxregion2";
	

	//用于策略添加到用户的测试
	public static String userName1="test01_subUser01";
	public static String userak1="ec722df7c43f7ace0949";
	public static String usersk1="d1fe8d0a300e650c4cae8d19c3564ee17a010fbe";
	
	public static String userName2="test01_subUser02";
	public static String userak2="76d57c26a4921374853a";
	public static String usersk2="eba5505023a5dcd2692f4eb97dd0d725a10af291";
	
	public static MetaClient metaClient = MetaClient.getGlobalClient();
	public static String groupName="createGroupForTest";
	public static String userName="createUserForTest";
	public static String policyName="createforTest";


	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	    CleanAndCreateUser();
	    Group group =new Group();
        group.accountId=accountId;
        group.groupName=groupName;
        group=HBaseUtils.get(group);
        if(group==null)
            IAMInterfaceTestUtils.CreateGroup(accessKey, secretKey, groupName, 200);
			
	}

	@Before
	public void setUp() throws Exception {
	    
	    
	}
	
	@AfterClass
	public static void after() throws Exception{
		HbaseUtils.TruncateTable("iam-group-yx");
	}
	
	public static void CleanAndCreateUser() throws Exception {
	    CleanTable.Clean_OOS();
	    CleanTable.Clean_IAM();
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

        VSNTagMeta dataTag1;
        VSNTagMeta metaTag1;
        
        
        dataTag1 = new VSNTagMeta("tag1", Arrays.asList(new String[] { dataregion1,dataregion2}), VSNTagType.DATA);
        metaClient.vsnTagInsert(dataTag1);
        metaTag1 = new VSNTagMeta("mtag1", Arrays.asList(new String[] {dataregion1  }), VSNTagType.META);
        metaClient.vsnTagInsert(metaTag1);
        
        UserToTagMeta user2Tag1 = new UserToTagMeta(owner.getId(),
                Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
        metaClient.userToTagInsert(user2Tag1);
        UserToTagMeta user2Tag2 = new UserToTagMeta(owner.getId(),
                Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
        metaClient.userToTagInsert(user2Tag2);
        
        String UserName1=userName1;
        User user1=new User();
        user1.accountId=accountId;
        user1.userName=UserName1;
        user1.userId="Test1Abc";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = user1.userId;
        aksk1.userName = UserName1;
        aksk1.accessKey=userak1;
        aksk1.setSecretKey(usersk1);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.userName=UserName1;
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
        
        String UserName2=userName2;
        User user2=new User();
        user2.accountId=accountId;
        user2.userName=UserName2;
        user2.userId="Test2Abc";
        user2.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user2);
            assertTrue(success);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        AkSkMeta aksk2 = new AkSkMeta(owner.getId());
        aksk2.isRoot = 0;
        aksk2.userId = user2.userId;
        aksk2.userName = UserName2;
        aksk2.accessKey=userak2;
        aksk2.setSecretKey(usersk2);
        metaClient.akskInsert(aksk2);
        user2.accessKeys = new ArrayList<>();
        user2.userName=UserName2;
        user2.accessKeys.add(aksk2.accessKey);
        HBaseUtils.put(user2);
     
    }
	
	/**
	 * put/get/del/head bucket，有iampolicy权限
	 * 对应资源bucketName（或*）
	 * 策略添加到用户
	 * 策略添加到组，组中用户有该策略权限
	 * 
	 * */
	@Test
	public void test_Bucket_iampolicy_allow_match() throws Exception{
		String policyName="createpolicyfortestBucket";
		
//		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
//		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
//		
//		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
//		assertEquals(200,result.first().intValue());
//		System.out.println(result.second());
//		//listbucket--getbucket
//		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
//		assertEquals(200,listResult.first().intValue());
//		System.out.println(listResult.second());
//		//listbucket--headbucket
//		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
//		assertEquals(200,headResult);
//		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
//		assertEquals(200,listMultiresult.first().intValue());
//		//删除创建的bucket
//		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
//		assertEquals(204,delResult.first().intValue());		
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName4, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName4, null);
		assertEquals(200,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName4, null);
		assertEquals(200,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName4, null);;
		assertEquals(200,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,userak2, usersk2, bucketName4, null);
		assertEquals(204,delResult2.first().intValue());
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		
	}
	
	/**
	 * Allow与NotResource：允许未显示列出的资源
	 * **/
	@Test
	public void test_Bucket_iampolicy_allow_match_NotResource() throws Exception{
		String policyName="createpolicyfortestBucket";
		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+"bucketname"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,listResult.first().intValue());
		System.out.println(listResult.second());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(200,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());		
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":bucketname*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);;
		assertEquals(200,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(204,delResult2.first().intValue());
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		
	}
	
		
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限
	 * **/
	@Test
	public void test_Bucket_iampolicy_allow_match_NotAction() throws Exception{
		String policyName="createpolicyfortestBucket";
		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"NotAction",Arrays.asList("oos:CreateBucket","oos:GetBuckets","oos:DeletesBucket","oos:listmultiuploadparts"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,listResult.first().intValue());
		System.out.println(result.second());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(200,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());		
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"NotAction",Arrays.asList("oos:CreateBucket","oos:GetBuckets","oos:DeletesBucket","oos:listmultiuploadparts"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);;
		assertEquals(200,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(204,delResult2.first().intValue());
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		
	}	
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限
	 * **/
	@Test
	public void test_Bucket_iampolicy_allow_match_NotActionNotResource() throws Exception{
		String policyName="createpolicyfortestBucket";
		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"NotAction",Arrays.asList("oos:CreateBucket","oos:GetBuckets","oos:DeletesBucket","oos:listmultiuploadparts"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":bucketname"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,listResult.first().intValue());
		System.out.println(result.second());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(200,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());		
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"NotAction",Arrays.asList("oos:CreateBucket","oos:GetBuckets","oos:DeletesBucket","oos:listmultiuploadparts"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":bucketName*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);;
		assertEquals(200,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(204,delResult2.first().intValue());
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		
	}		
	
	/**
	 * Resource允许的资源bucketname2,资源不匹配
	 * **/
	
	@Test
	public void test_Bucket_iampolicy_allow_notmatch_Resource() throws Exception{
		String policyName="createpolicyfortestBucket";
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "Local", null, dataregions, "Allowed", null);
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult.first().intValue());
		System.out.println(result.second());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult.first().intValue());		
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+bucketName2),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,headResult);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);;
		assertEquals(403,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,userak2, usersk2, bucketName, null);
		assertEquals(403,delResult2.first().intValue());
		
		OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		
	}	
	
	/**
	 * actions允许的操作不匹配
	 * **/	
	@Test
	public void test_Bucket_iampolicy_allow_notmatch_Action() throws Exception{
		String policyName="createpolicyfortestBucket";
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBuckets","oos:ListBucketss","oos:DeleteBucketss","oos:listmultiuploadparts"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "Local", null, dataregions, "Allowed", null);
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult.first().intValue());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult.first().intValue());		
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBuckets","oos:ListBucketss","oos:DeleteBucketss","oos:listmultiuploadparts"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);;
		assertEquals(403,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,userak2, usersk2, bucketName, null);
		assertEquals(403,delResult2.first().intValue());
		
		OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,accessKey, secretKey, bucketName, null);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		
	}	

	/**
	 * 有conditons，与conditions匹配,username
	 * */
	@Test
	public void test_Bucket_iampolicy_allow_conditions() throws Exception{
		String policyName="createpolicyfortestBucket";
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,listResult.first().intValue());
		System.out.println(result.second());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(200,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport,userak2, usersk2, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result12.first().intValue());
		OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport,accessKey, secretKey, bucketName, "Local", null, dataregions, "Allowed", null);
		//listbucket
		Pair<Integer,String> listResult12=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,listResult12.first().intValue());
		int headResult12=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,headResult12);
		Pair<Integer,String> listMultiresult12=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);;
		assertEquals(403,listMultiresult12.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult12=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delResult12.first().intValue());	
		OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		
		//修改策略，资源为*
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);
				
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);;
		assertEquals(200,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(204,delResult2.first().intValue());
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		
	}
	
	/**
	 * 有conditons，与conditions匹配,sourceIp
	 * */
	@Test
	public void test_Bucket_iampolicy_allow_conditions2() throws Exception{
		String policyName="createpolicyfortestBucket";
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});

		HashMap<String,String> param=new HashMap<>();
		param.put("X-Forwarded-For", "192.168.1.101");
		
		HashMap<String,String> param2=new HashMap<>();
		param2.put("X-Forwarded-For", "192.168.2.101");

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", param);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		//listbucket
		param.clear();
		param.put("X-Forwarded-For", "192.168.1.101");
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, param);
		assertEquals(200,listResult.first().intValue());
		System.out.println(listResult.second());
		param.clear();
		param.put("X-Forwarded-For", "192.168.1.101");
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, param);
		assertEquals(200,headResult);
		param.clear();
		param.put("X-Forwarded-For", "192.168.1.101");
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, param);;
		assertEquals(200,listMultiresult.first().intValue());
		//删除创建的bucket
		param.clear();
		param.put("X-Forwarded-For", "192.168.1.101");
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, param);
		assertEquals(204,delResult.first().intValue());	
		
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", param2);
		assertEquals(403,result12.first().intValue());
		OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "Local", null, dataregions, "Allowed", null);
		//listbucket
		param2.clear();
		param2.put("X-Forwarded-For", "192.168.2.101");
		Pair<Integer,String> listResult12=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, param2);
		assertEquals(403,listResult12.first().intValue());
		param2.clear();
		param2.put("X-Forwarded-For", "192.168.2.101");
		int headResult12=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, param2);
		assertEquals(403,headResult12);
		param2.clear();
		param2.put("X-Forwarded-For", "192.168.2.101");
		Pair<Integer,String> listMultiresult12=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, param2);;
		assertEquals(403,listMultiresult12.first().intValue());
		//删除创建的bucket
		param2.clear();
		param2.put("X-Forwarded-For", "192.168.2.101");
		Pair<Integer,String> delResult12=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, param2);
		assertEquals(403,delResult12.first().intValue());
		OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		
		//修改策略，资源为*
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("NotIpAddress","ctyun:SourceIp",Arrays.asList("192.168.2.1/24")));
        createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		param.clear();
		param.put("X-Forwarded-For", "192.168.1.101");
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", "Local", null, dataregions, "Allowed", param);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		param.clear();
		param.put("X-Forwarded-For", "192.168.1.101");
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", param);
		assertEquals(200,listResult2.first().intValue());
		param.clear();
		param.put("X-Forwarded-For", "192.168.1.101");
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", param);
		assertEquals(200,headResult2);
		param.clear();
		param.put("X-Forwarded-For", "192.168.1.101");
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", param);;
		assertEquals(200,listMultiresult2.first().intValue());
		//删除创建的bucket
		param.clear();
		param.put("X-Forwarded-For", "192.168.1.101");
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,userak2, usersk2, "createbucketbyuser2", param);
		assertEquals(204,delResult2.first().intValue());
		
		OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "Local", null, dataregions, "Allowed", null);
		
		param2.clear();
		param2.put("X-Forwarded-For", "192.168.2.101");
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport,userak2, usersk2, bucketName, "Local", null, dataregions, "Allowed", param2);
		assertEquals(403,result22.first().intValue());
		//listbucket
		param2.clear();
		param2.put("X-Forwarded-For", "192.168.2.101");
		Pair<Integer,String> listResult22=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, param2);
		assertEquals(403,listResult22.first().intValue());
		int headResult22=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, param2);
		assertEquals(403,headResult22);
		param2.clear();
		param2.put("X-Forwarded-For", "192.168.2.101");
		Pair<Integer,String> listMultiresult22=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, param2);;
		assertEquals(403,listMultiresult22.first().intValue());
		//删除创建的bucket
		param2.clear();
		param2.put("X-Forwarded-For", "192.168.2.101");
		Pair<Integer,String> delResult22=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, param2);
		assertEquals(403,delResult22.first().intValue());	
		OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		
	}
	
	/**
	 * 有conditons，与conditions匹配,currentTime
	 * */
	@Test
	public void test_Bucket_iampolicy_allow_conditions3() throws Exception{
		String policyName="createpolicyfortestBucket";
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThan","ctyun:CurrentTime",Arrays.asList("2019-01-01T00:00:00Z")));
//        conditions.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2019-09-20T00:00:00Z")));
		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,listResult.first().intValue());
		System.out.println(result.second());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(200,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());		
		
		//修改策略,conditions
		List<Condition> conditions2 = new ArrayList<Condition>();
		conditions2.add(IAMTestUtils.CreateCondition("DateLessThan","ctyun:CurrentTime",Arrays.asList("2019-09-10T00:00:00Z")));
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions2);
		
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result12.first().intValue());
		
		OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "Local", null, dataregions, "Allowed", null);
		
		//listbucket
		Pair<Integer,String> listResult12=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult12.first().intValue());
		int headResult12=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult12);
		Pair<Integer,String> listMultiresult12=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult12.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult12=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult12.first().intValue());
		
		//修改策略，添加策略到组
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(200,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, "createbucketbyuser2", null);;
		assertEquals(200,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport,userak2, usersk2, "createbucketbyuser2", null);
		assertEquals(204,delResult2.first().intValue());
		
		//修改策略，conditions
		createPolicy(accessKey,secretKey,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result22.first().intValue());
		//listbucket
		Pair<Integer,String> listResult22=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,listResult22.first().intValue());
		int headResult22=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,headResult22);
		Pair<Integer,String> listMultiresult22=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);;
		assertEquals(403,listMultiresult22.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult22=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delResult22.first().intValue());
		
		OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		
	}	

	/**
	 * 策略为deny，与deny策略匹配
	 * 无其他策略
	 * **/
	@Test
	public void test_Bucket_iampolicy_deny_match()throws Exception{
		String policyName="createpolicyfortestBucket";
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result.first().intValue());
		OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "Local", null, dataregions, "Allowed", null);
		
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult.first().intValue());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult.first().intValue());	
		
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result2.first().intValue());
		//listbucket
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult2.first().intValue());
		
		OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
        
	}
	
	/**
	 * 策略为deny,与deny不匹配
	 * 无其他策略,隐式拒绝
	 * **/
	@Test
	public void test_Bucket_iampolicy_deny_match_notActionORnotResourceOrConditions()throws Exception{
		String policyName="createpolicyfortestBucket";
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"NotAction",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result.first().intValue());
		OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "Local", null, dataregions, "Allowed", null);
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult.first().intValue());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult.first().intValue());
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result2.first().intValue());
		//listbucket
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult2.first().intValue());
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"NotAction",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result3.first().intValue());
		//listbucket
		Pair<Integer,String> listResult3=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult3.first().intValue());
		int headResult3=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult3);
		Pair<Integer,String> listMultiresult3=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult3.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult3=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult3.first().intValue());
		
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"NotAction",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result4.first().intValue());
		//listbucket
		Pair<Integer,String> listResult4=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult4.first().intValue());
		int headResult4=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult4);
		Pair<Integer,String> listMultiresult4=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult4.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult4=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult4.first().intValue());

		OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/**
	 * 策略为deny
	 * 存在其他策略；
	 * 若匹配，deny优先级高于allow，显示拒绝
	 * 若不匹配，验证其他策略
	 * 策略允许，且与之匹配，则允许访问
	 * ***/
	@Test
	public void test_Bucket_iampolicy_deny_match_existOtherPolicy()throws Exception{
		String policyName="createpolicyfortestBucket";
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createpolicyforallow","Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createpolicyforallow", 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result.first().intValue());
		OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, "Local", null, dataregions, "Allowed", null);
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult.first().intValue());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult.first().intValue());	
		
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringLike","ctyun:username",Arrays.asList("test01*")));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(403,result2.first().intValue());
		//listbucket
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(403,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delResult2.first().intValue());
		
		OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createpolicyforallow", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createpolicyforallow", 200);
        
	}
	
	/**
	 * 策略为deny
	 * 存在其他策略；
	 * 若匹配，deny优先级高于allow，显示拒绝
	 * 若不匹配，验证其他策略
	 * 策略允许，且与之匹配，则允许访问
	 * ***/	
	@Test
	public void test_Bucket_iampolicy_deny_notMatch_existOtherPolicy()throws Exception{
		String policyName="createpolicyfortestBucket";
		createPolicy(accessKey,secretKey,Effect.Allow,"createpolicyforallow","Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createpolicyforallow", 200);
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"NotAction",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result.first().intValue());
		//listbucket
		Pair<Integer,String> listResult=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,listResult.first().intValue());
		int headResult=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,headResult);
		Pair<Integer,String> listMultiresult=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(200,listMultiresult.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result2.first().intValue());
		//listbucket
		Pair<Integer,String> listResult2=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,listResult2.first().intValue());
		int headResult2=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,headResult2);
		Pair<Integer,String> listMultiresult2=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(200,listMultiresult2.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult2.first().intValue());
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"NotAction",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result3.first().intValue());
		//listbucket
		Pair<Integer,String> listResult3=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,listResult3.first().intValue());
		int headResult3=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,headResult3);
		Pair<Integer,String> listMultiresult3=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(200,listMultiresult3.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult3=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult3.first().intValue());
		
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName,"NotAction",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,result4.first().intValue());
		//listbucket
		Pair<Integer,String> listResult4=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,listResult4.first().intValue());
		int headResult4=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,headResult4);
		Pair<Integer,String> listMultiresult4=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);;
		assertEquals(200,listMultiresult4.first().intValue());
		//删除创建的bucket
		Pair<Integer,String> delResult4=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult4.first().intValue());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createpolicyforallow", 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createpolicyforallow", 200);
		
	}	
	
	/**
	 * getbucketalc/getbucketlocation
	 * 对应资源为bucketName（或*）
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_allow_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result4.first().intValue());
		System.out.println(result4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * Allow与NotResource：允许未显示列出的资源
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_allow_match_NotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result3.first().intValue());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result4.first().intValue());
		
		//修改策略为bucketName
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result21.first().intValue());
		
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result32.first().intValue());
		
		Pair<Integer,String> result42=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result42.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
		
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_allow_match_NotAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:PutBucketAcl","oos:PutBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:PutBucketAcl","oos:PutBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result4.first().intValue());
		System.out.println(result4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限,NotResource,允许未显示列出的资源
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_allow_match_NotActionNotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:PutBucketAcl","oos:PutBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result2.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result3.first().intValue());
				
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result4.first().intValue());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:PutBucketAcl","oos:PutBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:PutBucketAcl","oos:PutBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result32.first().intValue());
		System.out.println(result32.second());
				
		Pair<Integer,String> result42=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result42.first().intValue());
		System.out.println(result42.second());		
		
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	/**
	 * resource为bucketName2,与policy中的资源不匹配，访问拒绝
	 * 与actions中的操作不匹配，访问拒绝
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_allow_notMatch_ResourceOrAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result2.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result3.first().intValue());
				
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result4.first().intValue());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketAcl","oos:PutBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketAcl","oos:PutBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result32.first().intValue());
		System.out.println(result32.second());
				
		Pair<Integer,String> result42=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result42.first().intValue());
		System.out.println(result42.second());		
		
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * conditions，与conditions匹配
	 * 与conditions不匹配
	 * 
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_allow_match_conditions() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";	
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result2.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result12.first().intValue());
		
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result22.first().intValue());
		
		//修改策略
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);

		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result3.first().intValue());
				
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result4.first().intValue());
		
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result32.first().intValue());
		System.out.println(result32.second());
		
		Pair<Integer,String> result42=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result42.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * 测略为deny，匹配，显示拒绝
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_deny_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result2.first().intValue());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result3.first().intValue());

		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result4.first().intValue());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * 策略为deny，与策略不匹配，无其他策略，隐式拒绝
	 * NotAction,拒绝未显示列出的操作
	 * NotResource，拒绝未显示列出的资源
	 * conditions
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_deny_match_not() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result2.first().intValue());
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result12.first().intValue());

		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result3.first().intValue());

		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result4.first().intValue());

		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result32.first().intValue());

		Pair<Integer,String> result42=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result42.first().intValue());
		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result5=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result5.first().intValue());

		Pair<Integer,String> result6=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result6.first().intValue());
		
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
		
		Pair<Integer,String> result7=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result7.first().intValue());

		Pair<Integer,String> result8=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result8.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/**
	 * 存在allow策略，且匹配，存在deny策略，且匹配
	 * deny策略优先级高于allow
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_deny_match_existAllowPolicy() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result2.first().intValue());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result3.first().intValue());

		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result4.first().intValue());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 存在deny策略，不匹配
	 * 存在allow策略，且匹配
	 * **/
	@Test
	public void test_BucketAttribute_iampolicy_deny_notmatch_existAllowPolicy() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result2.first().intValue());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result3.first().intValue());

		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result4.first().intValue());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/**
	 * GetRegions/ListAllMyBuckets
	 * 对应资源为*
	 * **/
	@Test
	public void test_Buckets_iampolicy_allow_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "private");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(200,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(200,result4.first().intValue());
		System.out.println(result4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}

	/**
	 * GetRegions/ListAllMyBuckets
	 * 对应资源为*
	 * NotResource与allow，允许未显示列出的资源
	 * **/
	@Test
	public void test_Buckets_iampolicy_allow_match_notResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "private");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(403,result4.first().intValue());
		System.out.println(result4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/**
	 * GetRegions/ListAllMyBuckets
	 * 对应资源为*
	 * NotAction与allow，允许未显示列出的操作
	 * **/
	@Test
	public void test_Buckets_iampolicy_allow_match_notAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetRegion","oos:ListAllMyBuckets"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetRegion","oos:ListAllMyBuckets"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(200,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(200,result4.first().intValue());
		System.out.println(result4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * GetRegions/ListAllMyBucket
	 * 对应资源为*
	 * NotAction与allow，允许未显示列出的操作，与NotResource，允许未显示列出的资源
	 * **/
	@Test
	public void test_Buckets_iampolicy_allow_match_notActionNotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetRegion","oos:ListAllMyBuckets"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetRegion","oos:ListAllMyBuckets"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result12.first().intValue());
		System.out.println(result12.second());
		
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result22.first().intValue());
		System.out.println(result22.second());
		
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(200,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(200,result4.first().intValue());
		System.out.println(result4.second());
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetRegion","oos:ListAllMyBuckets"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(403,result32.first().intValue());
		System.out.println(result32.second());
		
		Pair<Integer,String> result42=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(403,result42.first().intValue());
		System.out.println(result42.second());		
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 存在一个allow策略，与策略中的action不匹配，隐式拒绝
	 * 与策略中的资源不匹配，隐式拒绝
	 * **/
	@Test
	public void test_Buckets_iampolicy_allow_notmatch() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegion","oos:ListAllMyBuckets"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result22.first().intValue());
		System.out.println(result22.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());	
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/**
	 * allow策略，secureTransport为true/false，使用https/http发送请求
	 * **/
	@Test
	public void test_Buckets_iampolicy_allow_conditions()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());

		String policyName2="createpolicyfortestBucketAttribute";
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("true")));

		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get("https", signVersion, jettyHttpsPort, userak1, usersk1, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get("https", signVersion, jettyHttpsPort, userak1, usersk1, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result22.first().intValue());
		System.out.println(result22.second());

		List<Condition> conditions2=new ArrayList<>();
		conditions2.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));

		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result4.first().intValue());
		System.out.println(result4.second());
		
		//删除bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());

		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 策略为deny(有/无conditions)，与策略匹配，显示拒绝
	 * **/
	@Test
	public void test_Buckets_iampolicy_deny_match()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());

		//修改策略
		User user2=new User();
		user2.accountId=accountId;
		user2.userName=userName2;
		user2=HBaseUtils.get(user2);
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","ctyun:userid",Arrays.asList(user2.userId)));
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(200,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(200,result4.first().intValue());
		System.out.println(result4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}

	/**
	 * 策略为deny，与策略不匹配，无其他策略，隐式拒绝
	 * NotAction,拒绝未显示列出的操作
	 * NotResource，拒绝未显示列出的资源
	 * conditions
	 * **/
	@Test
	public void test_Buckets_iampolicy_deny_match_not()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result4.first().intValue());
		System.out.println(result4.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		Pair<Integer,String> result5=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result5.first().intValue());
		System.out.println(result5.second());
				
		Pair<Integer,String> result6=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result6.first().intValue());
		System.out.println(result6.second());

		//修改策略
		User user=new User();
		user.accountId=accountId;
		user.userName=userName1;
		user=HBaseUtils.get(user);
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:userid",Arrays.asList(user.userId)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result7=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(403,result7.first().intValue());
		System.out.println(result7.second());
		
		Pair<Integer,String> result8=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak2, usersk2, null);
		assertEquals(403,result8.first().intValue());
		System.out.println(result8.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	/**
	 * 存在deny策略和allow策略
	 * 策略为deny(有/无conditions)，与策略匹配；与allow策略匹配
	 * deny策略优先级高于allow策略，显示拒绝
	 * **/
	@Test
	public void test_Buckets_iampolicy_deny_match_existallowpolicy()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());

		//修改策略
		User user=new User();
		user.accountId=accountId;
		user.userName=userName1;
		user=HBaseUtils.get(user);
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:userid",Arrays.asList(user.userId)));
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result4.first().intValue());
		System.out.println(result4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());	
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/**
	 * 存在deny策略和allow策略
	 * 与deny策略不匹配，判断，是否与allow策略匹配
	 * 与allow策略匹配，允许访问
	 * **/
	@Test
	public void test_Buckets_iampolicy_deny_notmatch_existallowpolicy()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		Pair<Integer,String> putresult2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, "Local", null, dataregions, "Allowed", null);
		assertEquals(200,putresult2.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		Pair<Integer,String> result=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());

		//修改策略
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("DateGreaterThanEquals","ctyun:CurrentTime",Arrays.asList("2019-09-19T00:00:00Z")));
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result3.first().intValue());
		System.out.println(result3.second());
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport, userak1, usersk1, null);
		assertEquals(200,result4.first().intValue());
		System.out.println(result4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		Pair<Integer,String> delResult2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName1, null);
		assertEquals(204,delResult2.first().intValue());	
		
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}

	/**
	 * put/get/dellifeCycle
	 * 对应资源为bucketName（或*）
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_allow_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(204,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * Allow与NotResource：允许未显示列出的资源
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_allow_match_NotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(204,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//修改策略为bucketName
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result21.first().intValue());
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());
		Pair<Integer,String> result23=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result23.first().intValue());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result31=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result31.first().intValue());
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result32.first().intValue());
		Pair<Integer,String> result33=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result33.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
		
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_allow_match_NotAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(204,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限,NotResource,允许未显示列出的资源
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_allow_match_NotActionNotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(204,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		System.out.println(getresult12.second());
		Pair<Integer,String> delresult12=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult12.first().intValue());
		System.out.println(delresult12.second());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result22.first().intValue());
		System.out.println(result22.second());
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		System.out.println(getresult22.second());
		Pair<Integer,String> delresult22=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult22.first().intValue());
		System.out.println(delresult22.second());	
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * resource为bucketName2,与policy中的资源不匹配，访问拒绝
	 * 与actions中的操作不匹配，访问拒绝
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_allow_notMatch_ResourceOrAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycle","oos:GetLifecycle"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result11.first().intValue());
		
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		
		Pair<Integer,String> delresult13=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult13.first().intValue());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycle","oos:GetLifecycle"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result21.first().intValue());
		
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		
		Pair<Integer,String> delresult23=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult23.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		
	
	/**
	 * conditions，与conditions匹配
	 * 与conditions不匹配
	 * 
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_allow_match_conditions() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";	
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delresult.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result11.first().intValue());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		Pair<Integer,String> result13=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result13.first().intValue());
		
		//修改策略
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());		
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(204,delresult2.first().intValue());
		
		Pair<Integer,String> lifecycle2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		assertEquals(200,lifecycle2.first().intValue());
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		Pair<Integer,String> delresult3=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult3.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		

	/**
	 * deny策略，显示拒绝
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_deny_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 策略为deny，与策略不匹配，无其他策略，隐式拒绝
	 * NotAction,拒绝未显示列出的操作
	 * NotResource，拒绝未显示列出的资源
	 * conditions
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_deny_match_not()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		System.out.println(getresult3.second());
		Pair<Integer,String> delresult3=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult3.first().intValue());
		System.out.println(delresult3.second());

		//修改策略
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result4.first().intValue());
		System.out.println(result4.second());
		Pair<Integer,String> getresult4=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult4.first().intValue());
		System.out.println(getresult4.second());
		Pair<Integer,String> delresult4=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult4.first().intValue());
		System.out.println(delresult4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * 存在deny策略和allow策略
	 * 策略为deny(有/无conditions)，与策略匹配；与allow策略匹配
	 * deny策略优先级高于allow策略，显示拒绝
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_deny_match_existallowpolicy()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 存在deny策略，不匹配
	 * 存在allow策略，且匹配
	 * **/
	@Test
	public void test_lifeCycle_iampolicy_deny_notmatch_existAllowPolicy() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(204,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * put/get/delwebSite
	 * 对应资源为bucketName（或*）
	 * **/
	@Test
	public void test_webSite_iampolicy_allow_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * Allow与NotResource：允许未显示列出的资源
	 * **/
	@Test
	public void test_webSite_iampolicy_allow_match_NotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//修改策略为bucketName
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result21.first().intValue());
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());
		Pair<Integer,String> result23=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result23.first().intValue());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result31=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result31.first().intValue());
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result32.first().intValue());
		Pair<Integer,String> result33=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result33.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
		
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限
	 * **/
	@Test
	public void test_webSite_iampolicy_allow_match_NotAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限,NotResource,允许未显示列出的资源
	 * **/
	@Test
	public void test_webSite_iampolicy_allow_match_NotActionNotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		System.out.println(getresult12.second());
		Pair<Integer,String> delresult12=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult12.first().intValue());
		System.out.println(delresult12.second());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result22.first().intValue());
		System.out.println(result22.second());
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		System.out.println(getresult22.second());
		Pair<Integer,String> delresult22=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult22.first().intValue());
		System.out.println(delresult22.second());	
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * resource为bucketName2,与policy中的资源不匹配，访问拒绝
	 * 与actions中的操作不匹配，访问拒绝
	 * **/
	@Test
	public void test_webSite_iampolicy_allow_notMatch_ResourceOrAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutWebsite","oos:GetWebsite","oos:DeleteWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result11.first().intValue());
		
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		
		Pair<Integer,String> delresult13=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult13.first().intValue());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutWebsite","oos:GetWebsite","oos:DeleteWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result21.first().intValue());
		
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		
		Pair<Integer,String> delresult23=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult23.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		
	
	/**
	 * conditions，与conditions匹配
	 * 与conditions不匹配
	 * 
	 * **/
	@Test
	public void test_webSite_iampolicy_allow_match_conditions() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";	
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result11.first().intValue());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		Pair<Integer,String> result13=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result13.first().intValue());
		
		//修改策略
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());		
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		
		Pair<Integer,String> putwebsite2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null);
		assertEquals(200,putwebsite2.first().intValue());
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		Pair<Integer,String> delresult3=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult3.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		

	/**
	 * deny策略，显示拒绝
	 * **/
	@Test
	public void test_webSite_iampolicy_deny_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 策略为deny，与策略不匹配，无其他策略，隐式拒绝
	 * NotAction,拒绝未显示列出的操作
	 * NotResource，拒绝未显示列出的资源
	 * conditions
	 * **/
	@Test
	public void test_webSite_iampolicy_deny_match_not()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		System.out.println(getresult3.second());
		Pair<Integer,String> delresult3=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult3.first().intValue());
		System.out.println(delresult3.second());

		//修改策略
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result4.first().intValue());
		System.out.println(result4.second());
		Pair<Integer,String> getresult4=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult4.first().intValue());
		System.out.println(getresult4.second());
		Pair<Integer,String> delresult4=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult4.first().intValue());
		System.out.println(delresult4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * 存在deny策略和allow策略
	 * 策略为deny(有/无conditions)，与策略匹配；与allow策略匹配
	 * deny策略优先级高于allow策略，显示拒绝
	 * **/
	@Test
	public void test_webSite_iampolicy_deny_match_existallowpolicy()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 存在deny策略，不匹配
	 * 存在allow策略，且匹配
	 * **/
	@Test
	public void test_webSite_iampolicy_deny_notmatch_existAllowPolicy() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketWebsite","oos:GetBucketWebsite","oos:DeleteBucketWebsite"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * put/get/delCors
	 * 对应资源为bucketName（或*）
	 * **/
	@Test
	public void test_Cors_iampolicy_allow_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * Allow与NotResource：允许未显示列出的资源
	 * **/
	@Test
	public void test_Cors_iampolicy_allow_match_NotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());
				
		//修改策略为bucketName
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result21.first().intValue());
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());
		Pair<Integer,String> result23=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result23.first().intValue());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result31=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result31.first().intValue());
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result32.first().intValue());
		Pair<Integer,String> result33=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result33.first().intValue());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
		
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限
	 * **/
	@Test
	public void test_Cors_iampolicy_allow_match_NotAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限,NotResource,允许未显示列出的资源
	 * **/
	@Test
	public void test_Cors_iampolicy_allow_match_NotActionNotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		System.out.println(getresult12.second());
		Pair<Integer,String> delresult12=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult12.first().intValue());
		System.out.println(delresult12.second());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result22.first().intValue());
		System.out.println(result22.second());
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		System.out.println(getresult22.second());
		Pair<Integer,String> delresult22=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult22.first().intValue());
		System.out.println(delresult22.second());	
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * resource为bucketName2,与policy中的资源不匹配，访问拒绝
	 * 与actions中的操作不匹配，访问拒绝
	 * **/
	@Test
	public void test_Cors_iampolicy_allow_notMatch_ResourceOrAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutCORS","oos:GetCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result11.first().intValue());
		
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		
		Pair<Integer,String> delresult13=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult13.first().intValue());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutCORS","oos:GetCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result21.first().intValue());
		
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		
		Pair<Integer,String> delresult23=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult23.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		
	
	/**
	 * conditions，与conditions匹配
	 * 与conditions不匹配
	 * 
	 * **/
	@Test
	public void test_Cors_iampolicy_allow_match_conditions() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";	
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());

		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result11.first().intValue());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		Pair<Integer,String> result13=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result13.first().intValue());
		
		//修改策略
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());		
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());

		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		Pair<Integer,String> delresult3=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult3.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		

	/**
	 * deny策略，显示拒绝
	 * **/
	@Test
	public void test_Cors_iampolicy_deny_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 策略为deny，与策略不匹配，无其他策略，隐式拒绝
	 * NotAction,拒绝未显示列出的操作
	 * NotResource，拒绝未显示列出的资源
	 * conditions
	 * **/
	@Test
	public void test_Cors_iampolicy_deny_match_not()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		System.out.println(getresult3.second());
		Pair<Integer,String> delresult3=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult3.first().intValue());
		System.out.println(delresult3.second());

		//修改策略
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result4.first().intValue());
		System.out.println(result4.second());
		Pair<Integer,String> getresult4=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult4.first().intValue());
		System.out.println(getresult4.second());
		Pair<Integer,String> delresult4=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult4.first().intValue());
		System.out.println(delresult4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * 存在deny策略和allow策略
	 * 策略为deny(有/无conditions)，与策略匹配；与allow策略匹配
	 * deny策略优先级高于allow策略，显示拒绝
	 * **/
	@Test
	public void test_Cors_iampolicy_deny_match_existallowpolicy()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 存在deny策略，不匹配
	 * 存在allow策略，且匹配
	 * **/
	@Test
	public void test_Cors_iampolicy_deny_notmatch_existAllowPolicy() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketCORS","oos:GetBucketCORS"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * put/get/dellogging
	 * 对应资源为bucketName（或*）
	 * **/
	@Test
	public void test_logging_iampolicy_allow_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * Allow与NotResource：允许未显示列出的资源
	 * **/
	@Test
	public void test_logging_iampolicy_allow_match_NotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());

		//修改策略为bucketName
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result21.first().intValue());
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result31=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result31.first().intValue());
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result32.first().intValue());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
		
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限
	 * **/
	@Test
	public void test_logging_iampolicy_allow_match_NotAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限,NotResource,允许未显示列出的资源
	 * **/
	@Test
	public void test_logging_iampolicy_allow_match_NotActionNotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());

		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		System.out.println(getresult12.second());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result22.first().intValue());
		System.out.println(result22.second());
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		System.out.println(getresult22.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * resource为bucketName2,与policy中的资源不匹配，访问拒绝
	 * 与actions中的操作不匹配，访问拒绝
	 * **/
	@Test
	public void test_logging_iampolicy_allow_notMatch_ResourceOrAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());

		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());

		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLogging","oos:GetLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result11.first().intValue());
		
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutLogging","oos:GetLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result21.first().intValue());
		
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		
	
	/**
	 * conditions，与conditions匹配
	 * 与conditions不匹配
	 * 
	 * **/
	@Test
	public void test_logging_iampolicy_allow_match_conditions() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";	
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result11.first().intValue());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult12.first().intValue());

		//修改策略
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());		

		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		

	/**
	 * deny策略，显示拒绝
	 * **/
	@Test
	public void test_logging_iampolicy_deny_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 策略为deny，与策略不匹配，无其他策略，隐式拒绝
	 * NotAction,拒绝未显示列出的操作
	 * NotResource，拒绝未显示列出的资源
	 * conditions
	 * **/
	@Test
	public void test_logging_iampolicy_deny_match_not()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		System.out.println(getresult3.second());

		//修改策略
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result4.first().intValue());
		System.out.println(result4.second());
		Pair<Integer,String> getresult4=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult4.first().intValue());
		System.out.println(getresult4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * 存在deny策略和allow策略
	 * 策略为deny(有/无conditions)，与策略匹配；与allow策略匹配
	 * deny策略优先级高于allow策略，显示拒绝
	 * **/
	@Test
	public void test_logging_iampolicy_deny_match_existallowpolicy()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 存在deny策略，不匹配
	 * 存在allow策略，且匹配
	 * **/
	@Test
	public void test_logging_iampolicy_deny_notmatch_existAllowPolicy() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketLogging","oos:GetBucketLogging"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * put/get/delAccelerate
	 * 对应资源为bucketName（或*）
	 * **/
	@Test
	public void test_Accelerate_iampolicy_allow_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * Allow与NotResource：允许未显示列出的资源
	 * **/
	@Test
	public void test_Accelerate_iampolicy_allow_match_NotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());

		//修改策略为bucketName
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result21.first().intValue());
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result31=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result31.first().intValue());
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result32.first().intValue());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
		
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限
	 * **/
	@Test
	public void test_Accelerate_iampolicy_allow_match_NotAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限,NotResource,允许未显示列出的资源
	 * **/
	@Test
	public void test_Accelerate_iampolicy_allow_match_NotActionNotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());

		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		System.out.println(getresult12.second());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result22.first().intValue());
		System.out.println(result22.second());
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		System.out.println(getresult22.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * resource为bucketName2,与policy中的资源不匹配，访问拒绝
	 * 与actions中的操作不匹配，访问拒绝
	 * **/
	@Test
	public void test_Accelerate_iampolicy_allow_notMatch_ResourceOrAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());

		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());

		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerate","oos:GetAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result11.first().intValue());
		
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerate","oos:GetAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result21.first().intValue());
		
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		
	
	/**
	 * conditions，与conditions匹配
	 * 与conditions不匹配
	 * 
	 * **/
	@Test
	public void test_Accelerate_iampolicy_allow_match_conditions() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";	
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result11.first().intValue());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult12.first().intValue());

		//修改策略
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());		

		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		

	/**
	 * deny策略，显示拒绝
	 * **/
	@Test
	public void test_Accelerate_iampolicy_deny_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 策略为deny，与策略不匹配，无其他策略，隐式拒绝
	 * NotAction,拒绝未显示列出的操作
	 * NotResource，拒绝未显示列出的资源
	 * conditions
	 * **/
	@Test
	public void test_Accelerate_iampolicy_deny_match_not()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		System.out.println(getresult3.second());

		//修改策略
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result4.first().intValue());
		System.out.println(result4.second());
		Pair<Integer,String> getresult4=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult4.first().intValue());
		System.out.println(getresult4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * 存在deny策略和allow策略
	 * 策略为deny(有/无conditions)，与策略匹配；与allow策略匹配
	 * deny策略优先级高于allow策略，显示拒绝
	 * **/
	@Test
	public void test_Accelerate_iampolicy_deny_match_existallowpolicy()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 存在deny策略，不匹配
	 * 存在allow策略，且匹配
	 * **/
	@Test
	public void test_Accelerate_iampolicy_deny_notmatch_existAllowPolicy() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);

		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutAccelerateConfiguration","oos:GetBucketAccelerate"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * put/get/delbucketpolicy
	 * 对应资源为bucketName（或*）
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_allow_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	/**
	 * Allow与NotResource：允许未显示列出的资源
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_allow_match_NotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString,null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//修改策略为bucketName
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result21.first().intValue());
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result22.first().intValue());
		Pair<Integer,String> result23=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result23.first().intValue());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result31=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result31.first().intValue());
		Pair<Integer,String> result32=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result32.first().intValue());
		Pair<Integer,String> result33=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,result33.first().intValue());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
		
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_allow_match_NotAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString,null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	
	
	/***
	 * Allow与NotAction，允许为actions未列出的操作权限,NotResource,允许未显示列出的资源
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_allow_match_NotActionNotResource() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result12=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result12.first().intValue());
		System.out.println(result12.second());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		System.out.println(getresult12.second());
		Pair<Integer,String> delresult12=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult12.first().intValue());
		System.out.println(delresult12.second());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"NotAction",Arrays.asList("oos:GetBucketAcl","oos:GetBucketLocation"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result22=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(403,result22.first().intValue());
		System.out.println(result22.second());
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		System.out.println(getresult22.second());
		Pair<Integer,String> delresult22=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult22.first().intValue());
		System.out.println(delresult22.second());	
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * resource为bucketName2,与policy中的资源不匹配，访问拒绝
	 * 与actions中的操作不匹配，访问拒绝
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_allow_notMatch_ResourceOrAction() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName2),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
				
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString,null);
		assertEquals(403,result2.first().intValue());
		
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutPolicy","oos:GetPolicy","oos:DeletePolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result11.first().intValue());
		
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		
		Pair<Integer,String> delresult13=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult13.first().intValue());
		
		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutPolicy","oos:GetPolicy","oos:DeletePolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		Pair<Integer,String> result21=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(403,result21.first().intValue());
		
		Pair<Integer,String> getresult22=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult22.first().intValue());
		
		Pair<Integer,String> delresult23=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult23.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		
	
	/**
	 * conditions，与conditions匹配
	 * 与conditions不匹配
	 * 
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_allow_match_conditions() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";	
		List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(200,result.first().intValue());
		
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());

		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		Pair<Integer,String> result11=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(403,result11.first().intValue());
		Pair<Integer,String> getresult12=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult12.first().intValue());
		Pair<Integer,String> result13=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,result13.first().intValue());
		
		//修改策略
		List<Condition> conditions2 = new ArrayList<Condition>();
        conditions2.add(IAMTestUtils.CreateCondition("StringNotEquals","ctyun:username",Arrays.asList("test01_subUser01")));
        
		createPolicy(accessKey,secretKey,Effect.Allow,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions2);

		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(200,result2.first().intValue());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());		
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
	
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		Pair<Integer,String> delresult3=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult3.first().intValue());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}		

	/**
	 * deny策略，显示拒绝
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_deny_match() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());

		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());

		//修改策略，资源为*
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 策略为deny，与策略不匹配，无其他策略，隐式拒绝
	 * NotAction,拒绝未显示列出的操作
	 * NotResource，拒绝未显示列出的资源
	 * conditions
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_deny_match_not()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());
		
		//修改策略
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
				
		Pair<Integer,String> result3=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result3.first().intValue());
		System.out.println(result3.second());
		Pair<Integer,String> getresult3=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult3.first().intValue());
		System.out.println(getresult3.second());
		Pair<Integer,String> delresult3=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult3.first().intValue());
		System.out.println(delresult3.second());

		//修改策略
		List<Condition> conditions=new ArrayList<>();
		conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:GetRegions","oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		
		Pair<Integer,String> result4=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(403,result4.first().intValue());
		System.out.println(result4.second());
		Pair<Integer,String> getresult4=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult4.first().intValue());
		System.out.println(getresult4.second());
		Pair<Integer,String> delresult4=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult4.first().intValue());
		System.out.println(delresult4.second());
		
		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);	     
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}	

	/**
	 * 存在deny策略和allow策略
	 * 策略为deny(有/无conditions)，与策略匹配；与allow策略匹配
	 * deny策略优先级高于allow策略，显示拒绝
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_deny_match_existallowpolicy()throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucket";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(403,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(403,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(403,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(403,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	/**
	 * 存在deny策略，不匹配
	 * 存在allow策略，且匹配
	 * **/
	@Test
	public void test_bucketPolicy_iampolicy_deny_notmatch_existAllowPolicy() throws Exception{
		String policyName="putgetdelheadbucketperssion";
		List<String> dataregions=Arrays.asList(new String[] {dataregion1,dataregion2});
		bucketIamPolicies(accessKey,secretKey,"putgetdelheadbucketperssion", userName1,policyName);
		//acl
		HashMap<String,String> headers=new HashMap<>();
		headers.put("x-amz-acl", "public-read");
		//创建bucket
		Pair<Integer,String> putresult=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, "Local", null, dataregions, "Allowed", headers);
		assertEquals(200,putresult.first().intValue());
		
		String policyName2="createpolicyfortestBucketAttribute";		
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),null);
		createPolicy(accessKey,secretKey,Effect.Allow,"createallowpolicy","Action",Arrays.asList("oos:PutBucketPolicy","oos:GetBucketPolicy","oos:DeleteBucketPolicy"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
		
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		
		String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal", Arrays.asList(new Principal("AWS", "*")), "Action", Arrays.asList("s3:*"), "Resource", Arrays.asList("arn:aws:s3:::" + bucketName+"/*"), null);		
		Pair<Integer,String> result=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, policyString, null);
		assertEquals(200,result.first().intValue());
		System.out.println(result.second());
		Pair<Integer,String> getresult=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,getresult.first().intValue());
		System.out.println(getresult.second());
		Pair<Integer,String> delresult=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(200,delresult.first().intValue());
		System.out.println(delresult.second());
		
		//修改策略，资源为*
		List<Condition> conditions = new ArrayList<Condition>();
		conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:username",Arrays.asList(userName2)));
		createPolicy(accessKey,secretKey,Effect.Deny,policyName2,"NotAction",Arrays.asList("oos:PutLifecycleConfiguration","oos:GetLifecycleConfiguration"),"NotResource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
				
		//将策略添加到组
		IAMInterfaceTestUtils.AddUserToGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.AttachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		
		Pair<Integer,String> result2=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, policyString, null);
		assertEquals(200,result2.first().intValue());
		System.out.println(result2.second());
		Pair<Integer,String> getresult2=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,getresult2.first().intValue());
		System.out.println(getresult2.second());
		Pair<Integer,String> delresult2=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyport, userak2, usersk2, bucketName, null);
		assertEquals(200,delresult2.first().intValue());
		System.out.println(delresult2.second());

		//删除创建的bucket
		Pair<Integer,String> delResult=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyport, userak1, usersk1, bucketName, null);
		assertEquals(204,delResult.first().intValue());	
		
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, policyName2, 200);
		IAMInterfaceTestUtils.DetachGroupPolicy(accessKey, secretKey, accountId, groupName, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, "createallowpolicy", 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName2, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, "createallowpolicy", 200);
		IAMInterfaceTestUtils.RemoveUserFromGroup(accessKey, secretKey, groupName, userName2, 200);
		IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
		IAMInterfaceTestUtils.DeletePolicy(accessKey, secretKey, accountId, policyName, 200);
		
	}
	
	@Test
	public void test_PutBucketAcl_private_StringLike_allow() {
	    String jettyhost="oos-"+regionName+".ctyunapi.cn";
	    
	    String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket12=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName1, "Local", null, null, null, params1);
        assertEquals(403, createbucket12.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
    }
	
	@Test
    public void test_PutBucketAcl_private_StringLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
	
	@Test
    public void test_PutBucketAcl_publicread_StringLike_allow() {
	    String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket22=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName1, "Local", null, null, null, params1);
        assertEquals(403, createbucket22.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
    }
	
	@Test
    public void test_PutBucketAcl_publicread_StringLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
	
	@Test
    public void test_PutBucketAcl_public_StringLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        Pair<Integer, String> createbucket32=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName1, "Local", null, null, null, params1);
        assertEquals(403, createbucket32.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
	
	@Test
    public void test_PutBucketAcl_public_StringLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
	
	@Test
    public void test_PutBucketAcl_readall_StringLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
    }
	
	@Test
    public void test_PutBucketAcl_readall_StringLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

    }
	
	@Test
    public void test_PutBucketAcl_private_StringNotLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
    }
    
    @Test
    public void test_PutBucketAcl_private_StringNotLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket12=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params1);
        assertEquals(200, createbucket12.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringNotLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringNotLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringNotLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringNotLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringNotLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringNotLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());

        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
	
	@Test
    public void test_PutBucketAcl_private_StringEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_private_StringEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());

        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_private_StringNotEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_private_StringNotEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringNotEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringNotEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringNotEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringNotEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringNotEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringNotEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());

        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_private_StringEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_private_StringEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_private_StringNotEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_private_StringNotEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringNotEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_publicread_StringNotEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringNotEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_public_StringNotEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringNotEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBucketAcl_readall_StringNotEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());

        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_NotPutBucket_hasXamzHeader() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "private");
        Pair<Integer, String> getbucket=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, params1);
        assertEquals(200, getbucket.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);    
    }
    
    @Test
    public void test_NotPutBucket_NoXamzHeader() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, null);
        assertEquals(403, createbucket1.first().intValue());
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> getbucket=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, null);
        assertEquals(200, getbucket.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_NotPutBucket_XamzHeaderError() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","oos:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "private11");
        Pair<Integer, String> getbucket=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, params1);
        assertEquals(200, getbucket.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket12=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName1, "Local", null, null, null, params1);
        assertEquals(403, createbucket12.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket22=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName1, "Local", null, null, null, params1);
        assertEquals(403, createbucket22.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        Pair<Integer, String> createbucket32=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName1, "Local", null, null, null, params1);
        assertEquals(403, createbucket32.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());

        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringNotLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringNotLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket12=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params1);
        assertEquals(200, createbucket12.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringNotLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringNotLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringNotLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringNotLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringNotLike_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringNotLike_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotLike","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());

        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());

        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringNotEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringNotEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringNotEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringNotEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringNotEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringNotEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringNotEquals_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringNotEquals_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEquals","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());

        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringNotEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_private_StringNotEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_private_deny";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringNotEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_publicread_StringNotEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_publicread";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public-read")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);

        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringNotEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_public_StringNotEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public-read-write")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringNotEqualsIgnoreCase_allow() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(200, createbucket3.first().intValue());
        
        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        // jetty 中要求此参数区分大小写
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(400, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(400, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(400, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_PutBuckets3Acl_readall_StringNotEqualsIgnoreCase_deny() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringNotEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("public*")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Deny,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        
        String policyName2="test_PutBucket_allow";
        String policyString2=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:PutBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName2, policyString2,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
        
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        HashMap<String, String> params2=new HashMap<String, String>();
        params2.put("x-amz-acl", "public-read");
        HashMap<String, String> params3=new HashMap<String, String>();
        params3.put("x-amz-acl", "public-read-write");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(403, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params2);
        assertEquals(403, createbucket2.first().intValue());
        
        Pair<Integer, String> createbucket3=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params3);
        assertEquals(403, createbucket3.first().intValue());

        HashMap<String, String> params4=new HashMap<String, String>();
        params4.put("x-amz-acl", "private".toUpperCase());
        HashMap<String, String> params5=new HashMap<String, String>();
        params5.put("x-amz-acl", "public-read".toUpperCase());
        HashMap<String, String> params6=new HashMap<String, String>();
        params6.put("x-amz-acl", "public-read-write".toUpperCase());
        
        Pair<Integer, String> createbucket4=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params4);
        assertEquals(403, createbucket4.first().intValue());
        
        Pair<Integer, String> createbucket5=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params5);
        assertEquals(403, createbucket5.first().intValue());
        
        Pair<Integer, String> createbucket6=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params6);
        assertEquals(403, createbucket6.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName2, 200);
    }
    
    @Test
    public void test_NotPutBucket_s3hasXamzHeader() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "private");
        Pair<Integer, String> getbucket=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, params1);
        assertEquals(200, getbucket.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
    }
    
    @Test
    public void test_NotPutBucket_s3NoXamzHeader() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, null);
        assertEquals(403, createbucket1.first().intValue());
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket2.first().intValue());
        
        Pair<Integer, String> getbucket=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, null);
        assertEquals(200, getbucket.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
    @Test
    public void test_NotPutBucket_s3XamzHeaderError() {
        String jettyhost="oos-"+regionName+".ctyunapi.cn";
        
        String policyName="test_PutBucketAcl_public";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEqualsIgnoreCase","s3:x-amz-acl",Arrays.asList("private")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, "Local", null, null, null, params);
        assertEquals(200, createbucket1.first().intValue());
        
        HashMap<String, String> params1=new HashMap<String, String>();
        params1.put("x-amz-acl", "private11");
        Pair<Integer, String> getbucket=OOSAPITestUtils.Bucket_Get(httpOrHttps, jettyhost, jettyport, signVersion, regionName, userak1, usersk1, bucketName, params1);
        assertEquals(200, getbucket.first().intValue());
        
        IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, userName1, policyName, 200);
    }
    
	//创建
	public void bucketIamPolicies(String ak, String sk, String action, String userName,String policyName) throws Exception{

		if(action.equals("putgetdelheadbucketperssion")){			
			createPolicy(ak,sk,Effect.Allow,policyName,"Action",Arrays.asList("oos:PutBucket","oos:ListBucket","oos:DeleteBucket","oos:ListBucketMultipartUploads"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
			User user=new User();
			user.accountId=accountId;
			user.userName=userName;
			user=HBaseUtils.get(user);			
			if(user!=null){
				IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
			}	
//			Group group=new Group();
//			group.accountId=accountId;
//			group.groupName=users;
//			group=HBaseUtils.get(group);
//			if(group!=null)
//				IAMInterfaceTestUtils.AttachGroupPolicy(ak, sk, accountId, users, policyName, 200);
		}

		
	}
	//创建策略
	public static String createPolicy(String ak,String sk,Effect effect,String policyName,String actionEffect,List<String> actions,String resourceEffect,List<String> resources,List<Condition> conditions)throws Exception{
		String policyDocument=IAMTestUtils.CreateOneStatementPolicyString(effect,null, null, actionEffect, actions, resourceEffect, resources, conditions);
		String body="Action=CreatePolicy&Version=2010-05-08&PolicyName="+URLEncoder.encode(policyName)+"&PolicyDocument="+URLEncoder.encode(policyDocument)+"&Description=test_des";
		Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
		assertEquals(200,result.first().intValue());
		return result.second();
	}

}
