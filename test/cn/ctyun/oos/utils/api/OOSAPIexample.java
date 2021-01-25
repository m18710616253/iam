package cn.ctyun.oos.utils.api;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import common.tuple.Pair;

public class OOSAPIexample {
    String host="oos-cd.ctyunapi.cn";
    String regionName="cd";
//    String accessKey="d5486d49a20339f164a5";
//    String secretKey="adf5f77f00e9dc5d39da406d00005e45e68b8b3d";
    public static final String accessKey="userak1";
    public static final String secretKey="usersk1";
    String httpOrHttps="https";
    int jettyPort=8444;
    String signVersion="V4";
    String bucketName1="yx-bucket-1";
    String bucketName2="yx-bucket-2";
    String dateregion1="yxregion1";
    String dateregion2="yxregion2";

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void test() {
        
        // 获取所有bucket列表
        Pair<Integer, String> listallmybucket=OOSAPITestUtils.Service_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(200, listallmybucket.first().intValue());
        System.out.println(listallmybucket.second());
        
        // 获取资源池中的索引位置和数据位置列表
        Pair<Integer, String> getregion=OOSAPITestUtils.Region_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, null);
        assertEquals(200, getregion.first().intValue());
        System.out.println(getregion.second());
        
        // 创建bucket
        Pair<Integer, String> createbucket1=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null, null, null, null, null);
        assertEquals(200, createbucket1.first().intValue());
        System.out.println(createbucket1.second());
        
        Pair<Integer, String> createbucket2=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", null);
        assertEquals(200, createbucket2.first().intValue());
        System.out.println(createbucket2.second());
//        
//        // 获取bucket的ACL信息
        Pair<Integer, String> getbucketacl=OOSAPITestUtils.Bucket_GetAcl(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketacl.first().intValue());
        System.out.println(getbucketacl.second());
        
        // 修改bucket acl属性
        HashMap<String, String> updateaclParams=new HashMap<String, String>();
        updateaclParams.put("x-amz-acl", "public-read-write");
        Pair<Integer, String> updatebucket=OOSAPITestUtils.Bucket_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, "Specified", null, Arrays.asList(dateregion1), "NotAllowed", updateaclParams);
        assertEquals(200, updatebucket.first().intValue());
        System.out.println(updatebucket.second());
        
        // 获取bucket的索引位置和数据位置 
        Pair<Integer, String> getbucketlocation=OOSAPITestUtils.Bucket_GetLocation(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlocation.first().intValue());
        System.out.println(getbucketlocation.second());
        
        // 创建，获取，删除bucketpolicy
        String policyString = "{" + "\"Version\": \"2012-10-17\","
                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
                + "\"Action\": \"s3:ListBucket\","
                + "\"Resource\": \"arn:aws:s3:::" + bucketName2 + "\","
                + "}]}";
        Pair<Integer, String> putbucketpolicy=OOSAPITestUtils.Bucket_PutPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, policyString, null);
        assertEquals(200, putbucketpolicy.first().intValue());
        System.out.println(putbucketpolicy.second());
        
        Pair<Integer, String> getbucketpolicy=OOSAPITestUtils.Bucket_GetPolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketpolicy.first().intValue());
        System.out.println(getbucketpolicy.second());
        
        Pair<Integer, String> delbucketpolicy=OOSAPITestUtils.Bucket_DeletePolicy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, delbucketpolicy.first().intValue());
        System.out.println(delbucketpolicy.second());
        
        // 创建，获取，删除website
        Pair<Integer, String> putbucketwebsite=OOSAPITestUtils.Bucket_PutWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, putbucketwebsite.first().intValue());
        System.out.println(putbucketwebsite.second());
        
        Pair<Integer, String> getbucketwebsite=OOSAPITestUtils.Bucket_GetWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketwebsite.first().intValue());
        System.out.println(getbucketwebsite.second());
        
        Pair<Integer, String> delbucketwebsite=OOSAPITestUtils.Bucket_DeleteWebsite(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, delbucketwebsite.first().intValue());
        System.out.println(delbucketwebsite.second());
        
        // 创建，获取logging
        Pair<Integer, String> putbucketlogging=OOSAPITestUtils.Bucket_PutLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, bucketName2,"logs/",null);
        assertEquals(200, putbucketlogging.first().intValue());
        System.out.println(putbucketlogging.second());
        
        Pair<Integer, String> getbucketlogging=OOSAPITestUtils.Bucket_GetLogging(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlogging.first().intValue());
        System.out.println(getbucketlogging.second());
        
        // 创建，获取，删除lifecycle
        Pair<Integer, String> putbucketlifecle=OOSAPITestUtils.Bucket_PutLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2,"logs","Enabled",30, null);
        assertEquals(200, putbucketlifecle.first().intValue());
        System.out.println(putbucketlifecle.second());
        
        Pair<Integer, String> getbucketlifecle=OOSAPITestUtils.Bucket_GetLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketlifecle.first().intValue());
        System.out.println(getbucketlifecle.second());
        
        Pair<Integer, String> delbucketlifecle=OOSAPITestUtils.Bucket_DeleteLifecycle(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(204, delbucketlifecle.first().intValue());
        System.out.println(delbucketlifecle.second());
        
        // 创建，获取cdn加速
        Pair<Integer, String> putbucketaccelerate=OOSAPITestUtils.Bucket_PutAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, Arrays.asList("192.168.1.1","192.168.2.1"),null);
        assertEquals(200, putbucketaccelerate.first().intValue());
        System.out.println(putbucketaccelerate.second());
        
        Pair<Integer, String> getbucketaccelerate=OOSAPITestUtils.Bucket_GetAccelerate(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketaccelerate.first().intValue());
        System.out.println(getbucketaccelerate.second());
        
        // 创建，获取，删除cors 
        Pair<Integer, String> putbucketcors=OOSAPITestUtils.Bucket_PutCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, putbucketcors.first().intValue());
        System.out.println(putbucketcors.second());
        
        Pair<Integer, String> getbucketcors=OOSAPITestUtils.Bucket_GetCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, getbucketcors.first().intValue());
        System.out.println(getbucketcors.second());
        
        Pair<Integer, String> delbucketcors=OOSAPITestUtils.Bucket_DeleteCors(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, delbucketcors.first().intValue());
        System.out.println(delbucketcors.second());
        
        // bucket中的object信息
        Pair<Integer, String> listobjects=OOSAPITestUtils.Bucket_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(200, listobjects.first().intValue());
        System.out.println(listobjects.second());
        
        // delete bucket
        Pair<Integer, String> delbucket=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName2, null);
        assertEquals(204, delbucket.first().intValue());
        System.out.println(delbucket.second());
        
        // put get head delete object
        HashMap<String, String> headers=new HashMap<String, String>();
        headers.put("Content-Type", "application/octet-stream;charset=utf-8");
        
        String objectName="src.txt";
        Pair<Integer, String> putobject=OOSAPITestUtils.Object_Put(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "first", headers);
        assertEquals(200, putobject.first().intValue());
        System.out.println(putobject.second());
        
        Pair<Integer, String> getobject=OOSAPITestUtils.Object_Get(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(200, getobject.first().intValue());
        System.out.println(getobject.second());
        
        int headobject=OOSAPITestUtils.Object_Head(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(200, headobject);
        
        Pair<Integer, String> delobject=OOSAPITestUtils.Object_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, null);
        assertEquals(204, delobject.first().intValue());
        System.out.println(delobject.second());
        
        // post object
        Pair<Integer, String> postobject=OOSAPITestUtils.Object_Post(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, "post.txt", null);
        assertEquals(204, postobject.first().intValue());
        System.out.println(postobject.second());
        
        // copy object
        String objectName2="desc.txt";
        Pair<Integer, String> copyobject=OOSAPITestUtils.Object_Copy(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName, objectName2, null);
        assertEquals(200, copyobject.first().intValue());
        System.out.println(copyobject.second());
        
        // 分段上传，1.init 2.uploadpart,3.copy part,4.List Multipart Uploads,5.list part 6.Complete Multipart Upload,7.Abort Multipart Upload
        String objectName3="muli.txt";
        Pair<Integer, String> initmuli=OOSAPITestUtils.Object_InitialMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, null);
        assertEquals(200, initmuli.first().intValue());
        String uploadId=OOSAPITestUtils.getMultipartUploadId(initmuli.second());
        
        Pair<Integer, String> uploadpart=OOSAPITestUtils.Object_UploadPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 1, "123", null);
        assertEquals(200, uploadpart.first().intValue());
        String etag1=uploadpart.second();
        Pair<Integer, String> copypart=OOSAPITestUtils.Object_CopyPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, 2, objectName, null);
        assertEquals(200, copypart.first().intValue());
        String etag2=OOSAPITestUtils.getCopyPartEtag(copypart.second());
        
        OOSAPITestUtils.Bucket_ListMultipartUploads(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        
        Pair<Integer, String> listpart=OOSAPITestUtils.Object_ListPart(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(200, listpart.first().intValue());
        System.out.println(listpart.second());
        
        Map<String, String> partEtagMap = new HashMap<String, String>();
        partEtagMap.put("1", etag1);
        partEtagMap.put("2", etag2);

        Pair<Integer, String> completemultipart=OOSAPITestUtils.Object_CompleteMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1,objectName3, uploadId, partEtagMap, null);
        assertEquals(200, completemultipart.first().intValue());
        System.out.println(completemultipart.second());
        
        Pair<Integer, String> aboutmultipart=OOSAPITestUtils.object_AbortMultipartUpload(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, objectName3, uploadId, null);
        assertEquals(204, aboutmultipart.first().intValue());
        System.out.println(aboutmultipart.second());
        
        // delete mulit 
        Pair<Integer, String> delobjects=OOSAPITestUtils.Object_DeleteMulit(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, Arrays.asList(objectName,objectName2,objectName3), null);
        assertEquals(200, delobjects.first().intValue());
        System.out.println(delobjects.second());
        
        // delete bucket
        Pair<Integer, String> delbucket2=OOSAPITestUtils.Bucket_Delete(httpOrHttps, host, jettyPort, signVersion, regionName, accessKey, secretKey, bucketName1, null);
        assertEquals(204, delbucket2.first().intValue());
        System.out.println(delbucket2.second());
    }

}
