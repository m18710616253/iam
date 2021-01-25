package cn.ctyun.oos.iam.test.oosaccesscontrol;

import static org.junit.Assert.*;

import java.io.StringReader;
import java.net.HttpURLConnection;
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
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;

import cn.ctyun.oos.iam.accesscontroller.policy.Principal;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import common.tuple.Pair;
/**
 * 
 * @author yanxiao
 * 兼容性测试，新ak可以在旧的oos和iam上正常运行，旧ak可以在新的oos和iam上运行
 * 用户的aksk要用6.4.1之前的代码创建的。创建的aksk中不包含cdate列的主ak
 * 需要根据ownerName1 = "test_user4_6463084869102845087@a.cn"修改accountId
 */
public class CompatibleTest {
    public static String accessKey = "d5486d49a20339f164a5";
    public static String secretKey = "adf5f77f00e9dc5d39da406d00005e45e68b8b3d"; 
    public static String accountId="3k3yoqmzsnjpd";
    
    public static int jettyPort_New=80;
    public static int jettyPort_Old=8080;
    public static int iamPort_New=9460;
    public static int iamPort_Old=8097;
    
    public static String httpOrHttps="http";
    public static String signVersion="V2";
    public static String bucketName1="yx-bucket-1";
    public static String bucketName2="yx-bucket-2";
    
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

    }

    @Before
    public void setUp() throws Exception {
    }
    
    @Test
    /*
     *
     */
    public void test_oldAK_NewOOSAndIAM() {
        // 旧iam创建ak
        Pair<Integer, String> createak=OOSInterfaceTestUtils.CreateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, null);
        assertEquals(200, createak.first().intValue());
        Pair<String, String> aksk=getAKSk(createak.second());
        
        String ak=aksk.first();
        String sk=aksk.second();
        
        System.out.println("----------------------");
        System.out.println(ak);
        System.out.println(sk);
        
//      String ak="f476b34bbf9acab57cd1";
//      String sk="14b4eee6dda12fea84725bd91aa7d6a1465cf266";
        
        // 修改ak为主ak
        Pair<Integer, String> setAkPrimary=OOSInterfaceTestUtils.UpdateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, ak, "Active", "true", null);
        assertEquals(200, setAkPrimary.first().intValue());
        
        // 新api
        Pair<Integer, String> serviceGet=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyPort_New, ak, sk, null);
        assertEquals(200, serviceGet.first().intValue());
        Pair<Integer, String> regionGet=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyPort_New, ak, sk, null);
        assertEquals(200, regionGet.first().intValue());
        Pair<Integer, String> createbucket1=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName2, null, null, null, null, null);
        assertEquals(200, createbucket2.first().intValue());
        Pair<Integer, String> delbucket2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName2, null);
        assertEquals(204, delbucket2.first().intValue());
        
        Pair<Integer, String> getbucket1Location=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, getbucket1Location.first().intValue());  
        Pair<Integer, String> getbucket1ACL=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, getbucket1ACL.first().intValue());  
        Pair<Integer, String> listobject=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, listobject.first().intValue());
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName1),null);
        Pair<Integer, String> putpolicy=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, policyString, null);
        assertEquals(200, putpolicy.first().intValue());
        
        Pair<Integer, String> getpolicy=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, getpolicy.first().intValue());
      
        Pair<Integer, String> delpolicy=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, delpolicy.first().intValue());
      
        Pair<Integer, String> putWebsite=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, putWebsite.first().intValue());
      
        Pair<Integer, String> getWebsite=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, getWebsite.first().intValue());
      
        Pair<Integer, String> delWebsite=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, delWebsite.first().intValue());
      
        Pair<Integer, String> listMulti=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, listMulti.first().intValue());
          
        Pair<Integer, String> putLogging=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, putLogging.first().intValue());
          
        Pair<Integer, String> getLogging=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, getLogging.first().intValue());
          
        int headBucket=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, headBucket);
          
        Pair<Integer, String> putLifecycle=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, putLifecycle.first().intValue());
          
        Pair<Integer, String> getLifecycle=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, getLifecycle.first().intValue());
          
        Pair<Integer, String> delLifecycle=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(204, delLifecycle.first().intValue());
      
        Pair<Integer, String> putAccelerate=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, putAccelerate.first().intValue());
          
        Pair<Integer, String> getAccelerate=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, getAccelerate.first().intValue());
          
        Pair<Integer, String> putCors=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, putCors.first().intValue());
          
        Pair<Integer, String> getCors=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, getCors.first().intValue());
          
        Pair<Integer, String> delCors=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
        assertEquals(200, delCors.first().intValue());
          
        String objectName1="1.txt";
        Pair<Integer, String> putObject=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, objectName1,"put 1...", null);
        assertEquals(200, putObject.first().intValue());
          
        Pair<Integer, String> getObject=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, objectName1, null);
        assertEquals(200, getObject.first().intValue());

        String objectName2="copy.txt";
          
        Pair<Integer, String> copyObject=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, objectName1,objectName2, null);
        assertEquals(200, copyObject.first().intValue());
          
        int headObject=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, objectName2, null);
        assertEquals(200, headObject);
          
        String objectName3="post.txt";
        Pair<Integer, String> postObject=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, objectName3,"post....", null);
        assertEquals(204, postObject.first().intValue());
          
        String objectName4="mulit.txt";
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, objectName4,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
          
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, objectName4,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
          
        Pair<Integer, String> copyPartResult2=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, objectName4,uploadId,2,objectName1,null);
        assertEquals(200, copyPartResult2.first().intValue()); 
        partEtagMap.put("2", getCopyPartEtag(copyPartResult2.second()));
          
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyPort_New,ak, sk, bucketName1,objectName4, uploadId,null);
        assertEquals(200, ListPartResult.first().intValue()); 
          
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyPort_New,ak, sk, bucketName1,objectName4, uploadId, partEtagMap,null);
        assertEquals(200, completeResult.first().intValue()); 
          
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyPort_New,ak, sk, bucketName1,objectName4, uploadId, null);
        assertEquals(204, aborteResult.first().intValue());  
          
          
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1,objectName3,null);
        assertEquals(204, getresult1.first().intValue());
          
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_DeleteMulit(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1,Arrays.asList(objectName1,objectName2),null);
        assertEquals(200, delresult1.first().intValue());
           
        // 新iam
        String userName="testUser1";
        String groupName="testGroup1";
        List<Pair<String, String>> tags= new ArrayList<Pair<String,String>>();
        Pair<String, String> tag1=new Pair<String, String>();
        tag1.first("phone");
        tag1.second("12345678901");
        tags.add(tag1);
        
        IAMInterfaceTestUtils.CreateUser(ak, sk, userName, 200);
        IAMInterfaceTestUtils.CreateGroup(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.ListGroups(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.GetGroup(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.AddUserToGroup(ak, sk, groupName, userName, 200);
        IAMInterfaceTestUtils.ListGroupsForUser(ak, sk, userName, 200);
        IAMInterfaceTestUtils.RemoveUserFromGroup(ak, sk, groupName, userName, 200);
        
        IAMInterfaceTestUtils.GetUser(ak, sk, userName, 200);
        IAMInterfaceTestUtils.TagUser(ak, sk, userName, tags, 200);
        IAMInterfaceTestUtils.ListUserTags(ak, sk, userName, 200);
        IAMInterfaceTestUtils.UntagUser(ak, sk, userName, Arrays.asList(tag1.first()), 200);
        
        IAMInterfaceTestUtils.CreateLoginProfile(ak, sk, userName, "a12345678", 200);
        IAMInterfaceTestUtils.UpdateLoginProfile(ak, sk, userName, "b12345678", 200);
        IAMInterfaceTestUtils.DeleteLoginProfile(ak, sk, userName, 200);

        String deviceName="mymfa1";
        String xml=IAMInterfaceTestUtils.CreateMFADevice(ak, sk, deviceName, 200);
        Pair<String, String> devicePair=getMFADeviceSerialNumber(xml);
        String SerialNumber=devicePair.first();
        String base32StringSeed=devicePair.second();
        Pair<String, String> codesPair=CreateIdentifyingCode(base32StringSeed);
        IAMInterfaceTestUtils.EnableMFADevice(ak, sk, userName, accountId, deviceName, codesPair.first(), codesPair.second(), 200);
        IAMInterfaceTestUtils.ListVirtualMFADevices(ak, sk, 200);
        IAMInterfaceTestUtils.ListMFADevices(ak, sk, userName, 200);
        IAMInterfaceTestUtils.DeactivateMFADevice(ak, sk, userName, accountId, deviceName, 200);
        IAMInterfaceTestUtils.DeleteVirtualMFADevice(ak, sk, accountId, deviceName, 200);
        
        IAMInterfaceTestUtils.GetAccountPasswordPolicy(ak, sk, 200);
        IAMInterfaceTestUtils.UpdateAccountPasswordPolicy(ak, sk, 200);
        IAMInterfaceTestUtils.DeleteAccountPasswordPolicy(ak, sk, 200);
        
        String policyName ="AllowALLIAM";
        String iampolicyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("iam:*"),"Resource",Arrays.asList("arn:ctyun:iam::"+accountId+"*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, iampolicyString,200);
        IAMInterfaceTestUtils.GetPolicy(ak, sk, accountId, policyName, 200); 
        IAMInterfaceTestUtils.ListPolicies(ak, sk, 200);
        IAMInterfaceTestUtils.AttachGroupPolicy(ak, sk, accountId, groupName, policyName, 200);
        IAMInterfaceTestUtils.ListAttachedGroupPolicies(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(ak, sk, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.ListAttachedUserPolicies(ak, sk, userName, 200);
        IAMInterfaceTestUtils.ListEntitiesForPolicy(ak, sk, accountId, policyName, 200);
        IAMInterfaceTestUtils.DetachGroupPolicy(ak, sk, accountId, groupName, policyName, 200);
        IAMInterfaceTestUtils.DetachUserPolicy(ak, sk, accountId, userName, policyName, 200);
        IAMInterfaceTestUtils.DeletePolicy(ak, sk, accountId, policyName, 200);
        
        IAMInterfaceTestUtils.DeleteGroup(ak, sk, groupName, 200);
        IAMInterfaceTestUtils.DeleteUser(ak, sk, userName, 200);
        
        NewIAmListAccessKeys(ak, sk, 200);
        NewIAmUpdateAccessKey(ak, sk, ak, "Active", 200);
        NewIAmDeleteAccessKey(ak, sk, ak, 200);
        
    }
    
    @Test
    /*
     *
     */
    public void test_NewAK_OldOOSAndIAM() {
        //新ak
        String xml=NewIAmCreateAccessKey(accessKey, secretKey, 200);
        Pair<String, String> aksk=getAKSk(xml);
        
        String ak=aksk.first();
        String sk=aksk.second();
        
//        String ak="4c98e92b46e7431eeb05";
//        String sk="dadfe57651a85071892e5de2ed5a3519f5239a2f";
         
        
        // 旧api
        Pair<Integer, String> serviceGet=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyPort_Old, ak, sk, null);
        assertEquals(200, serviceGet.first().intValue());
        Pair<Integer, String> regionGet=OOSInterfaceTestUtils.Region_Get(httpOrHttps, signVersion, jettyPort_Old, ak, sk, null);
        assertEquals(200, regionGet.first().intValue());
        Pair<Integer, String> createbucket1=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        
        Pair<Integer, String> createbucket2=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName2, null, null, null, null, null);
        assertEquals(200, createbucket2.first().intValue());
        Pair<Integer, String> delbucket2=OOSInterfaceTestUtils.Bucket_Delete(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName2, null);
        assertEquals(204, delbucket2.first().intValue());
        
        Pair<Integer, String> getbucket1Location=OOSInterfaceTestUtils.Bucket_GetLocation(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, getbucket1Location.first().intValue());  
        Pair<Integer, String> getbucket1ACL=OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, getbucket1ACL.first().intValue());  
        Pair<Integer, String> listobject=OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, listobject.first().intValue());
        
        List<Principal> principals=new ArrayList<Principal>();
        principals.add(Principal.AllUsers);
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",principals,"Action",Arrays.asList("s3:ListBucket"),"Resource",Arrays.asList("arn:aws:s3:::"+bucketName1),null);
        Pair<Integer, String> putpolicy=OOSInterfaceTestUtils.Bucket_PutPolicy(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, policyString, null);
        assertEquals(200, putpolicy.first().intValue());
        
        Pair<Integer, String> getpolicy=OOSInterfaceTestUtils.Bucket_GetPolicy(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, getpolicy.first().intValue());
      
        Pair<Integer, String> delpolicy=OOSInterfaceTestUtils.Bucket_DeletePolicy(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, delpolicy.first().intValue());
      
        Pair<Integer, String> putWebsite=OOSInterfaceTestUtils.Bucket_PutWebsite(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, putWebsite.first().intValue());
      
        Pair<Integer, String> getWebsite=OOSInterfaceTestUtils.Bucket_GetWebsite(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, getWebsite.first().intValue());
      
        Pair<Integer, String> delWebsite=OOSInterfaceTestUtils.Bucket_DeleteWebsite(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, delWebsite.first().intValue());
      
        Pair<Integer, String> listMulti=OOSInterfaceTestUtils.Bucket_ListMultipartUploads(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, listMulti.first().intValue());
          
        Pair<Integer, String> putLogging=OOSInterfaceTestUtils.Bucket_PutLogging(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, putLogging.first().intValue());
          
        Pair<Integer, String> getLogging=OOSInterfaceTestUtils.Bucket_GetLogging(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, getLogging.first().intValue());
          
        int headBucket=OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, headBucket);
          
        Pair<Integer, String> putLifecycle=OOSInterfaceTestUtils.Bucket_PutLifecycle(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, putLifecycle.first().intValue());
          
        Pair<Integer, String> getLifecycle=OOSInterfaceTestUtils.Bucket_GetLifecycle(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, getLifecycle.first().intValue());
          
        Pair<Integer, String> delLifecycle=OOSInterfaceTestUtils.Bucket_DeleteLifecycle(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(204, delLifecycle.first().intValue());
      
        Pair<Integer, String> putAccelerate=OOSInterfaceTestUtils.Bucket_PutAccelerate(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, putAccelerate.first().intValue());
          
        Pair<Integer, String> getAccelerate=OOSInterfaceTestUtils.Bucket_GetAccelerate(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, getAccelerate.first().intValue());
          
        Pair<Integer, String> putCors=OOSInterfaceTestUtils.Bucket_PutCors(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, putCors.first().intValue());
          
        Pair<Integer, String> getCors=OOSInterfaceTestUtils.Bucket_GetCors(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, getCors.first().intValue());
          
        Pair<Integer, String> delCors=OOSInterfaceTestUtils.Bucket_DeleteCors(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, null);
        assertEquals(200, delCors.first().intValue());
          
        String objectName1="1.txt";
        Pair<Integer, String> putObject=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, objectName1,"put 1...", null);
        assertEquals(200, putObject.first().intValue());
          
        Pair<Integer, String> getObject=OOSInterfaceTestUtils.Object_Get(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, objectName1, null);
        assertEquals(200, getObject.first().intValue());

        String objectName2="copy.txt";
          
        Pair<Integer, String> copyObject=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, objectName1,objectName2, null);
        assertEquals(200, copyObject.first().intValue());
          
        int headObject=OOSInterfaceTestUtils.Object_Head(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, objectName2, null);
        assertEquals(200, headObject);
          
        String objectName3="post.txt";
        Pair<Integer, String> postObject=OOSInterfaceTestUtils.Object_Post(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, objectName3,"post....", null);
        assertEquals(204, postObject.first().intValue());
          
        String objectName4="mulit.txt";
        Pair<Integer, String> initresult1=OOSInterfaceTestUtils.Object_InitialMultipartUpload(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, objectName4,null);
        assertEquals(200, initresult1.first().intValue()); 
        String uploadId=getMultipartUploadId(initresult1.second());
        System.err.println("uploadId="+uploadId);
        Map<String, String> partEtagMap = new HashMap<String, String>();
          
        Pair<Integer, String> uploadPartResult1=OOSInterfaceTestUtils.Object_UploadPart(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, objectName4,uploadId,1,"uploadpart1",null);
        assertEquals(200, uploadPartResult1.first().intValue()); 
        partEtagMap.put("1", uploadPartResult1.second());
          
        Pair<Integer, String> copyPartResult2=OOSInterfaceTestUtils.Object_CopyPart(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1, objectName4,uploadId,2,objectName1,null);
        assertEquals(200, copyPartResult2.first().intValue()); 
        partEtagMap.put("2", getCopyPartEtag(copyPartResult2.second()));
          
        Pair<Integer, String> ListPartResult=OOSInterfaceTestUtils.Object_ListPart(httpOrHttps, signVersion, jettyPort_Old,ak, sk, bucketName1,objectName4, uploadId,null);
        assertEquals(200, ListPartResult.first().intValue()); 
          
        Pair<Integer, String> completeResult=OOSInterfaceTestUtils.Object_CompleteMultipartUpload(httpOrHttps, signVersion, jettyPort_Old,ak, sk, bucketName1,objectName4, uploadId, partEtagMap,null);
        assertEquals(200, completeResult.first().intValue()); 
          
        Pair<Integer, String> aborteResult=OOSInterfaceTestUtils.object_AbortMultipartUpload(httpOrHttps, signVersion, jettyPort_Old,ak, sk, bucketName1,objectName4, uploadId, null);
        assertEquals(204, aborteResult.first().intValue());  
          
          
        Pair<Integer, String> getresult1=OOSInterfaceTestUtils.Object_Delete(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1,objectName3,null);
        assertEquals(204, getresult1.first().intValue());
          
        Pair<Integer, String> delresult1=OOSInterfaceTestUtils.Object_DeleteMulit(httpOrHttps, signVersion, jettyPort_Old, ak, sk, bucketName1,Arrays.asList(objectName1,objectName2),null);
        assertEquals(200, delresult1.first().intValue());
        
        // 旧iam
        Pair<Integer, String> createak1=OOSInterfaceTestUtils.CreateAccessKey(httpOrHttps, signVersion, iamPort_Old, ak, sk, null);
        assertEquals(200, createak1.first().intValue());
        Pair<String, String> aksk1=getAKSk(createak1.second());
        
        String ak1=aksk1.first();
        String sk1=aksk1.second();
        
        Pair<Integer, String> setAkPrimary=OOSInterfaceTestUtils.UpdateAccessKey(httpOrHttps, signVersion, iamPort_Old, ak, sk, ak1, "Active", "true", null);
        assertEquals(200, setAkPrimary.first().intValue());
        
        Pair<Integer, String> listKeys=OOSInterfaceTestUtils.ListAccessKey(httpOrHttps, signVersion, iamPort_Old, ak, sk, null);
        assertEquals(200, listKeys.first().intValue());
        
        Pair<Integer, String> delkey1=OOSInterfaceTestUtils.DeleteAccessKey(httpOrHttps, signVersion, iamPort_Old, ak, sk, ak1, null);
        assertEquals(200, delkey1.first().intValue());
        
        Pair<Integer, String> delkey2=OOSInterfaceTestUtils.DeleteAccessKey(httpOrHttps, signVersion, iamPort_Old, ak, sk, ak, null);
        assertEquals(200, delkey2.first().intValue());
    }


    @Test
    /*
     *
     */
    public void test_oldAKNotPrimaryKey_NewOOS() {
        // 旧iam创建ak普通key
        Pair<Integer, String> createak=OOSInterfaceTestUtils.CreateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, null);
        assertEquals(200, createak.first().intValue());
        Pair<String, String> aksk=getAKSk(createak.second());
        
        String ak=aksk.first();
        String sk=aksk.second();
        
//        String ak="5d3ae3a72bc83818e0e6";
//        String sk="797591ea94260644fb25fe222caca088c1280b5e";
        
//        System.out.println(ak);
//        System.out.println(sk);
        
        // 新oos
        // 不能创建，删除，修改bucket
//        Pair<Integer, String> bucketPut=OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null, null, null, null, null);
//        assertEquals(403, bucketPut.first().intValue());
//        
//        // 上传对象名称必须以ak开头
//        Pair<Integer, String> objectPut=OOSInterfaceTestUtils.Object_Put(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, ak+"hello.txt", "abc", null);
//        assertEquals(200, objectPut.first().intValue());
//        // list object prefix以ak开头
//        Pair<Integer, String> objectlist=OOSInterfaceTestUtils.Bucket_GetPrefix(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, null);
//        assertEquals(200, objectlist.first().intValue());
//        // 新iam主key删除ak
        
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyPort_New,ak, sk, bucketName1, "Local", null, null, null, params);
//        Pair<Integer, String> copy=OOSInterfaceTestUtils.Object_Copy(httpOrHttps, signVersion, jettyPort_New, ak, sk, bucketName1, "put.txt", ak+"copy1.txt", null);
//        assertEquals(200, copy.first().intValue());
//        NewIAmDeleteAccessKey(accessKey, secretKey, ak, 200);
    }
    
    @Test
    public void test_OldAK_NewIAMOpAK() {
        // 旧api 共创建7个ak,4个主ak,
        Pair<Integer, String> createak1=OOSInterfaceTestUtils.CreateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, null);
        assertEquals(200, createak1.first().intValue());
        Pair<String, String> aksk1=getAKSk(createak1.second());
        String ak1=aksk1.first();
        String sk1=aksk1.second();
        
        Pair<Integer, String> createak2=OOSInterfaceTestUtils.CreateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, null);
        assertEquals(200, createak2.first().intValue());
        Pair<String, String> aksk2=getAKSk(createak2.second());
        String ak2=aksk2.first();
        String sk2=aksk2.second();
        
        
        Pair<Integer, String> createak3=OOSInterfaceTestUtils.CreateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, null);
        assertEquals(200, createak3.first().intValue());
        Pair<String, String> aksk3=getAKSk(createak3.second());
        String ak3=aksk3.first();
        String sk3=aksk3.second();
        
        
        Pair<Integer, String> createak4=OOSInterfaceTestUtils.CreateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, null);
        assertEquals(200, createak4.first().intValue());
        Pair<String, String> aksk4=getAKSk(createak4.second());
        String ak4=aksk4.first();
        String sk4=aksk4.second();
        
        Pair<Integer, String> createak5=OOSInterfaceTestUtils.CreateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, null);
        assertEquals(200, createak5.first().intValue());
        Pair<String, String> aksk5=getAKSk(createak5.second());
        String ak5=aksk5.first();
        String sk5=aksk5.second();
        
        Pair<Integer, String> createak6=OOSInterfaceTestUtils.CreateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, null);
        assertEquals(200, createak6.first().intValue());
        Pair<String, String> aksk6=getAKSk(createak6.second());
        String ak6=aksk6.first();
        String sk6=aksk6.second();
        
        OOSInterfaceTestUtils.UpdateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, ak1, "Active", "true", null);
        OOSInterfaceTestUtils.UpdateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, ak2, "Active", "true", null);
        OOSInterfaceTestUtils.UpdateAccessKey(httpOrHttps, signVersion, iamPort_Old, accessKey, secretKey, ak3, "Active", "true", null);
        
        // 新api list
       NewIAmListAccessKeys(accessKey, secretKey, 200);
        
        // 新api 更新ak
       NewIAmUpdateAccessKey(accessKey, secretKey, ak2, "Inactive", 200);
       NewIAmUpdateAccessKey(accessKey, secretKey, ak5, "Inactive", 200);
       
       NewIAmListAccessKeys(accessKey, secretKey, 200);
       
        // 新api 删除主 ak到一个，创建ak
       NewIAmDeleteAccessKey(accessKey, secretKey, ak1, 200);
       NewIAmDeleteAccessKey(accessKey, secretKey, ak2, 200);
       NewIAmDeleteAccessKey(accessKey, secretKey, ak3, 200);
       NewIAmDeleteAccessKey(accessKey, secretKey, ak4, 200);
       NewIAmDeleteAccessKey(accessKey, secretKey, ak5, 200);
       NewIAmDeleteAccessKey(accessKey, secretKey, ak6, 200);
       String xml=NewIAmCreateAccessKey(accessKey, secretKey, 200);
       Pair<String, String> aksk7=getAKSk(xml);
       String ak7=aksk7.first();
       String sk7=aksk7.second();
       NewIAmDeleteAccessKey(accessKey, secretKey, ak7, 200);
    }
    
    
    public static String NewIAmCreateAccessKey(String ak,String sk,int expectedCode) {
        String body="Action=CreateAccessKey";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String NewIAmDeleteAccessKey(String ak,String sk,String akId,int expectedCode) {
        String body="Action=DeleteAccessKey&AccessKeyId="+akId;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String NewIAmListAccessKeys(String ak,String sk,int expectedCode) {
        String body="Action=ListAccessKeys";
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public static String NewIAmUpdateAccessKey(String ak,String sk,String akId,String status,int expectedCode) {
        String body="Status="+status+"&Action=UpdateAccessKey&AccessKeyId="+akId;
        Pair<Integer,String> result=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        assertEquals(expectedCode, result.first().intValue());
        return result.second();    
    }
    
    public Pair<String, String> getAKSk(String xml) {
        Pair<String, String> aksk= new Pair<String, String>();
        
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            
            Element createAKResultElement=root.getChild("CreateAccessKeyResult");
            Element AkElement=createAKResultElement.getChild("AccessKey");
            
            String ak=AkElement.getChild("AccessKeyId").getValue();
            aksk.first(ak);
            String sk=AkElement.getChild("SecretAccessKey").getValue();
            aksk.second(sk);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return aksk;
    }
    
    public String getMultipartUploadId(String xml) {
        String uploadId="";
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            @SuppressWarnings("unchecked")
            List<Element> secondLevel=root.getChildren();
            
           uploadId=secondLevel.get(2).getText();
        } catch (Exception e) {
            e.printStackTrace();;
        }
        
        return uploadId;
    }
    
    public String getCopyPartEtag(String xml) {
        String etag="";
        try {
            StringReader sr = new StringReader(xml);
            InputSource is = new InputSource(sr);
            Document doc = (new SAXBuilder()).build(is);
            Element root = doc.getRootElement();
            @SuppressWarnings("unchecked")
            List<Element> secondLevel=root.getChildren();
            
            etag=secondLevel.get(1).getText();
        } catch (Exception e) {
            e.printStackTrace();;
        }
        
        return etag;
    }
    
    public Pair<String, String> getMFADeviceSerialNumber(String xml) {
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
