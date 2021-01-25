package cn.ctyun.oos.iam.test.oosaccesscontrol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.apache.hadoop.conf.Configuration;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.OwnerMeta;
import common.tuple.Pair;

public class OOSAccessControlTest {
    
    public static final String OOS_IAM_DOMAIN="https://oos-cd-iam.ctyunapi.cn:9460/";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String regionName="cd";
    
    private static String ownerName = "root_user@test.com";
    public static final String accessKey="userak";
    public static final String secretKey="usersk";
    
    public static final String user1Name="test_1";
    public static final String user2Name="test_2";
    public static final String user3Name="Abc1";
    public static final String user1accessKey1="abcdefghijklmnop";
    public static final String user1secretKey1="cccccccccccccccc";
    public static final String user1accessKey2="1234567890123456";
    public static final String user1secretKey2="user1secretKey2lllll";
    public static final String user2accessKey="qrstuvwxyz0000000";
    public static final String user2secretKey="bbbbbbbbbbbbbbbbbb";
    public static final String user3accessKey="abcdefgh12345678";
    public static final String user3secretKey="3333333333333333";
    
    public static String accountId="3rmoqzn03g6ga";
    public static String mygroupName="mygroup";
    
    public static final int jettyHttpPort=80;
    public static final int jettyHttpsPort=8444;
    
    public static final String httpOrHttps="http";
    public static final int jettyport=jettyHttpPort;
    
//    public static final String httpOrHttps="https";
//    public static final int jettyport=jettyHttpsPort;
    
    public static final String signVersion="V4";
    
    
    
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();
    static Configuration globalConf = GlobalHHZConfig.getConfig();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

//        IAMTestUtils.TrancateTable("oos-aksk-yx");
//        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
//        
//        // 创建根用户
//        owner.email=ownerName;
//        owner.setPwd("123456");
//        owner.maxAKNum=10;
//        owner.displayName="测试根用户";
//        owner.bucketCeilingNum=10;
//        metaClient.ownerInsertForTest(owner);
//        
//        AkSkMeta aksk=new AkSkMeta(owner.getId());
//        aksk.accessKey=accessKey;
//        aksk.setSecretKey(secretKey);
//        aksk.isPrimary=1;
//        metaClient.akskInsert(aksk);
//        
//        
//        String UserName1=user1Name;
//        User user1=new User();
//        user1.accountId=accountId;
//        user1.userName=UserName1;
//        user1.userId="test1abc";
//        user1.createDate=System.currentTimeMillis();
//        try {
//            boolean success=HBaseUtils.checkAndCreate(user1);
//            assertTrue(success);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//
//        // 插入数据库aksk
//        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
//        aksk1.isRoot = 0;
//        aksk1.userId = user1.userId;
//        aksk1.userName = UserName1;
//        aksk1.accessKey=user1accessKey1;
//        aksk1.setSecretKey(user1secretKey1);
//        metaClient.akskInsert(aksk1);
//        user1.accessKeys = new ArrayList<>();
//        user1.accessKeys.add(aksk1.accessKey);
//        
//        aksk1.accessKey=user1accessKey2;
//        aksk1.setSecretKey(user1secretKey2);
//        metaClient.akskInsert(aksk1);
//        user1.accessKeys.add(aksk1.accessKey);
//        HBaseUtils.put(user1);
//        
//        String UserName2=user2Name;
//        User user2=new User();
//        user2.accountId=accountId;
//        user2.userName=UserName2;
//        user2.userId="Test1Abc";
//        user2.createDate=System.currentTimeMillis();
//        try {
//            boolean success=HBaseUtils.checkAndCreate(user2);
//            assertTrue(success);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//        
//        AkSkMeta aksk2 = new AkSkMeta(owner.getId());
//        aksk2.isRoot = 0;
//        aksk2.userId = user2.userId;
//        aksk2.userName = UserName2;
//        aksk2.accessKey=user2accessKey;
//        aksk2.setSecretKey(user2secretKey);
//        metaClient.akskInsert(aksk2);
//        user2.accessKeys = new ArrayList<>();
//        user2.userName=UserName2;
//        user2.accessKeys.add(aksk2.accessKey);
//        HBaseUtils.put(user2);
//        
//        String UserName3=user3Name;
//        User user3=new User();
//        user3.accountId=accountId;
//        user3.userName=UserName3;
//        user3.userId="abc1";
//        user3.createDate=System.currentTimeMillis();
//        try {
//            boolean success=HBaseUtils.checkAndCreate(user3);
//            assertTrue(success);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//        
//        AkSkMeta aksk3 = new AkSkMeta(owner.getId());
//        aksk3.isRoot = 0;
//        aksk3.userId = user3.userId;
//        aksk3.userName = UserName3;
//        aksk3.accessKey=user3accessKey;
//        aksk3.setSecretKey(user3secretKey);
//        metaClient.akskInsert(aksk3);
//        
//        user3.accessKeys = new ArrayList<>();
//        user3.userName=UserName3;
//        user3.accessKeys.add(aksk3.accessKey);
//        HBaseUtils.put(user3);   
//        
//        HBaseAdmin globalHbaseAdmin = new HBaseAdmin(globalConf);
//        
//        HBaseUserToTag.dropTable(GlobalHHZConfig.getConfig());
//        HBaseUserToTag.createTable(globalHbaseAdmin);
//        HBaseVSNTag.dropTable(GlobalHHZConfig.getConfig());
//        HBaseVSNTag.createTable(globalHbaseAdmin);
//        Thread.sleep(1000);
//        
//        VSNTagMeta dataTag1;
//        VSNTagMeta metaTag1;
//        
//        
//        dataTag1 = new VSNTagMeta("tag1", Arrays.asList(new String[] { "yxregion1","yxregion2"}), VSNTagType.DATA);
//        metaClient.vsnTagInsert(dataTag1);
//        metaTag1 = new VSNTagMeta("mtag1", Arrays.asList(new String[] { "yxregion1" }), VSNTagType.META);
//        metaClient.vsnTagInsert(metaTag1);
//        
//        UserToTagMeta user2Tag1 = new UserToTagMeta(owner.getId(),
//                Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
//        metaClient.userToTagInsert(user2Tag1);
//        UserToTagMeta user2Tag2 = new UserToTagMeta(owner.getId(),
//                Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
//        metaClient.userToTagInsert(user2Tag2);
//        
//        
//        HBaseUsageCurrent.dropTable(GlobalHHZConfig.getConfig());
//        HBaseUsageCurrent.createTable(globalHbaseAdmin);
//        
//        metaClient.usageCurrentInit(owner.getId(), 0L, 0L, 0L, 0L,
//                "yxregion1");
//        metaClient.usageCurrentInit(owner.getId(), 0L, 0L, 0L, 0L,
//                "yxregion2");
//        metaClient.usageCurrentInit(owner.getId(), 0L, 0L,0L, 0L,
//                Consts.GLOBAL_DATA_REGION);
    }

    @Before
    public void setUp() throws Exception {
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
//        OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, "yx-bucket-1", null,null,null,null,null);
    }
    
    @Test
    public void test_Allow_ListAllMyBucket_Condtion_IpAddress() {
        String policyName="allowspecialIP";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("IpAddress","ctyun:SourceIp",Arrays.asList("192.168.1.1/24","192.168.3.1")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        // 不符合condition
        Pair<Integer, String> user1get1=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1,null);
        assertEquals(403, user1get1.first().intValue());
        AssertAccessDeniedString(user1get1.second(), "ListAllMyBucket", user1Name, "*");
        // 符合condition
        HashMap<String, String> headers = new HashMap<String, String>();
        headers.put("X-Forwarded-For","192.168.1.101");
        Pair<Integer, String> user1get2=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport,user1accessKey1, user1secretKey1,headers);
        assertEquals(200, user1get2.first().intValue());
        assertTrue(user1get2.second().contains("ListAllMyBucketsResult"));
        // user2没有给权限
        HashMap<String, String> headers2 = new HashMap<String, String>();
        headers2.put("X-Forwarded-For","192.168.1.101");
        Pair<Integer, String> user2get=OOSInterfaceTestUtils.Service_Get(httpOrHttps, signVersion, jettyport,user2accessKey, user2secretKey,headers2);
        assertEquals(403, user2get.first().intValue());
        AssertAccessDeniedString(user2get.second(), "ListAllMyBucket", user2Name, "*");
    }
    
    @Test
    public void test_Allow_GetRegions_Condtion_SSL() {
        String policyName="allowspecialIP";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("Bool","ctyun:SecureTransport",Arrays.asList("false")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:GetRegions"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        Pair<Integer, String> user1http=OOSInterfaceTestUtils.Region_Get("http", signVersion, 80, user1accessKey1, user1secretKey1, null);
        assertEquals(200, user1http.first().intValue());
        assertTrue(user1http.second().contains("BucketRegions"));
        
        Pair<Integer, String> user2http=OOSInterfaceTestUtils.Region_Get("http", signVersion, 80, user2accessKey, user2secretKey, null);
        assertEquals(403, user2http.first().intValue());
        AssertAccessDeniedString(user2http.second(), "GetRegions", user2Name, "*");
        
        Pair<Integer, String> user1https=OOSInterfaceTestUtils.Region_Get("https", signVersion, 8444, user1accessKey1, user1secretKey1, null);
        assertEquals(403, user1https.first().intValue());
        AssertAccessDeniedString(user1https.second(), "GetRegions", user1Name, "*");
        
        
    }
    
    @Test
    public void test_Allow_ListBucket_Conditon_UserAgent_StringEquals() {
        
        String policyName="allowspecialIP";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","ctyun:UserAgent",Arrays.asList("Java/1.8.0")));
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName,200);
        
        OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, "yx-bucket-1", null);
//        OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, "yx-bucket-1", null);
        
//        HashMap<String, String> headers = new HashMap<String, String>();
//        headers.put("User-Agent","Java/1.8.0");
//        OOSInterfaceTestUtils.Bucket_Head(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, "yx-bucket-1", headers);
        
//        HashMap<String, String> headers2 = new HashMap<String, String>();
//        headers2.put("User-Agent","Java/1.8.0");
//        OOSInterfaceTestUtils.Bucket_Get(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, "yx-bucket-1", headers2);
        
    }
    
    
    
    public void AssertAccessDeniedString(String xml,String methodString,String userName,String resource) {
        try {
            JSONObject error=IAMTestUtils.ParseErrorToJson(xml);
            assertEquals("AccessDenied", error.get("Code"));
            assertEquals("User: arn:ctyun:iam::3rmoqzn03g6ga:user/"+userName+" is not authorized to perform: oos:"+methodString+" on resource: arn:ctyun:oos::3rmoqzn03g6ga:"+resource+".", error.get("Message"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }

    @Test
    public void test() {
//        OOSInterfaceTestUtils.Service_Get("http", "V4", accessKey, secretKey, null);
        
//        OOSInterfaceTestUtils.Region_Get("http", "V2", 80, accessKey, secretKey);
//        OOSInterfaceTestUtils.Region_Get("http", "V4", 80, accessKey, secretKey, null);
//        OOSInterfaceTestUtils.Region_Get("https", "V2", 8444, accessKey, secretKey, null);
//        OOSInterfaceTestUtils.Region_Get("https", "V4", 8444, accessKey, secretKey, null);
        
//        OOSInterfaceTestUtils.Bucket_Put("http", "V2", 80,accessKey, secretKey, "yx-bucket-2", null,null,null,null,null);
//        OOSInterfaceTestUtils.Bucket_Put("http", "V4", 80,accessKey, secretKey, "yx-bucket-2", null,null,null,null,null);

//        OOSInterfaceTestUtils.Bucket_Put("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2", "public-read-write",null,null,null,null);
//        OOSInterfaceTestUtils.Bucket_Put("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2", "public-read","Specified",null,Arrays.asList("yxregion1"),"Allowed");
//        OOSInterfaceTestUtils.Bucket_GetLocation("http", "V2", 80,accessKey, secretKey, "yx-bucket-2", null);
//        OOSInterfaceTestUtils.Bucket_GetLocation("http", "V4", 80,accessKey, secretKey, "yx-bucket-2", null);
//        OOSInterfaceTestUtils.Bucket_GetLocation("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetLocation("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2", null);
//        OOSInterfaceTestUtils.Bucket_GetAcl("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetAcl("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetAcl("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetAcl("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_Get("https", "V4", accessKey, secretKey, "yx-bucket-1", null);
//        OOSInterfaceTestUtils.Bucket_Get("https", "V2", accessKey, secretKey, "yx-bucket-1", null);
//        OOSInterfaceTestUtils.Bucket_Get("http", "V2", accessKey, secretKey, "yx-bucket-1", null);
//        OOSInterfaceTestUtils.Bucket_Delete("http", "V2", 80,accessKey, secretKey, "yx-bucket-2", null);
//        OOSInterfaceTestUtils.Bucket_Delete("http", "V4", 80,accessKey, secretKey, "yx-bucket-2", null);
//        OOSInterfaceTestUtils.Bucket_Delete("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2", null);
//        OOSInterfaceTestUtils.Bucket_Delete("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2", null);

//        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,"Principal",Arrays.asList("AWS:*"),"Action",Arrays.asList("oos:ListBucket"),"Resource",Arrays.asList("*"),null);
//        String json = "{" + "\"Version\": \"2012-10-17\","
//                + "\"Id\": \"preventHotLinking\"," + "\"Statement\": [" + " {"
//                + " \"Sid\": \"1\"," + "\"Effect\": \"Allow\","
//                + "\"Principal\": {" + " \"AWS\": \"*\"" + "},"
//                + "\"Action\": \"s3:PutObject\","
//                + "\"Resource\": \"arn:aws:s3:::" + "yx-bucket-2" + "/*\","
//                + "\"Condition\": {" + "\"StringEquals\": {"
//                + "\"aws:Referer\": ["
//                + "\"http://yourwebsitename.com/login.html\","
//                + "\"http://www.yourwebsitename.com/login.html\"" + "]}}}]}";
//        OOSInterfaceTestUtils.Bucket_PutPolicy("http", "V2", 80,accessKey, secretKey, "yx-bucket-2", json);
//        OOSInterfaceTestUtils.Bucket_GetPolicy("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeletePolicy("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_PutPolicy("http", "V4", 80,accessKey, secretKey, "yx-bucket-2", json);
//        OOSInterfaceTestUtils.Bucket_GetPolicy("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeletePolicy("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_PutPolicy("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2", json);
//        OOSInterfaceTestUtils.Bucket_GetPolicy("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeletePolicy("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
//        
//        OOSInterfaceTestUtils.Bucket_PutPolicy("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2", json);
//        OOSInterfaceTestUtils.Bucket_GetPolicy("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeletePolicy("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_PutWebsite("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetWebsite("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeleteWebsite("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        
//        OOSInterfaceTestUtils.Bucket_PutWebsite("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetWebsite("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeleteWebsite("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_ListMultipartUploads("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_ListMultipartUploads("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_ListMultipartUploads("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_ListMultipartUploads("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_PutLogging("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetLogging("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_PutLogging("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetLogging("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_Head("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_Head("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_PutLifecycle("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetLifecycle("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeleteLifecycle("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
//        
//        OOSInterfaceTestUtils.Bucket_PutLifecycle("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetLifecycle("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeleteLifecycle("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_PutAccelerate("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetAccelerate("http", "V2", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_PutAccelerate("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetAccelerate("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Bucket_PutCors("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetCors("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeleteCors("http", "V4", 80,accessKey, secretKey, "yx-bucket-2");
//        
//        OOSInterfaceTestUtils.Bucket_PutCors("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_GetCors("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
//        OOSInterfaceTestUtils.Bucket_DeleteCors("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2");
        
//        OOSInterfaceTestUtils.Object_Put("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","first.txt","hello world!");
//        OOSInterfaceTestUtils.Object_Get("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","first.txt");
//        OOSInterfaceTestUtils.Object_Delete("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","first.txt");
//        
//        OOSInterfaceTestUtils.Object_Put("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","first.txt","hello world!");
//        OOSInterfaceTestUtils.Object_Get("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","first.txt");
//        OOSInterfaceTestUtils.Object_Delete("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","first.txt");
//        OOSInterfaceTestUtils.Object_Copy("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","first.txt","second.txt");
//        OOSInterfaceTestUtils.Object_Copy("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","first.txt","third.txt");
        
//        OOSInterfaceTestUtils.Object_InitialMultipartUpload("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","mulit5.txt");
//        String uploadId="1567478549704196100";
//        OOSInterfaceTestUtils.Object_UploadPart("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","mulit5.txt",uploadId,1,"123");
//        OOSInterfaceTestUtils.Object_UploadPart("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","mulit5.txt",uploadId,2,"456");
//        
//        OOSInterfaceTestUtils.Object_ListPart("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","mulit1.txt", uploadId);
//        OOSInterfaceTestUtils.Object_ListPart("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2","mulit1.txt", uploadId);
//        
//        OOSInterfaceTestUtils.object_AbortMultipartUpload("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","mulit1.txt", uploadId);
        
//        OOSInterfaceTestUtils.object_AbortMultipartUpload("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2","mulit5.txt", uploadId);
        
//        Map<String, String> partEtagMap = new HashMap<String, String>();
//        partEtagMap.put("1", "\"202cb962ac59075b964b07152d234b70\"");
//        partEtagMap.put("2", "\"250cf8b51c773f3f8dc8b4be867a9a02\"");
//        
//        OOSInterfaceTestUtils.Object_CompleteMultipartUpload("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","mulit1.txt", uploadId, partEtagMap);
//        
//        OOSInterfaceTestUtils.Object_Get("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","mulit1.txt");
        
        
//        OOSInterfaceTestUtils.Object_InitialMultipartUpload("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","mulit2.txt");
//        String uploadId="1567474402391370400";
//        OOSInterfaceTestUtils.Object_UploadPart("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","mulit2.txt",uploadId,1,"abc");
//        OOSInterfaceTestUtils.Object_UploadPart("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","mulit2.txt",uploadId,2,"def");
//        
//        Map<String, String> partEtagMap = new HashMap<String, String>();
//        partEtagMap.put("1", "\"900150983cd24fb0d6963f7d28e17f72\"");
//        partEtagMap.put("2", "\"4ed9407630eb1000c0f6b63842defa7d\"");
//        
//        OOSInterfaceTestUtils.Object_CompleteMultipartUpload("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","mulit2.txt", uploadId, partEtagMap);
//        
//        OOSInterfaceTestUtils.Object_Get("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","mulit2.txt");
        
//        OOSInterfaceTestUtils.Object_Put("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","put1.txt", "!@#");
//        
//        OOSInterfaceTestUtils.Object_InitialMultipartUpload("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","mulit4.txt");
//        String uploadId="1567475528907338300";
//        OOSInterfaceTestUtils.Object_CopyPart("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2","mulit4.txt",uploadId,1, "put1.txt");
//        OOSInterfaceTestUtils.Object_UploadPart("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","mulit4.txt",uploadId,2,"abc");
//        OOSInterfaceTestUtils.Object_CopyPart("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","mulit4.txt",uploadId,3, "put1.txt");
////        
//        Map<String, String> partEtagMap = new HashMap<String, String>();
//        partEtagMap.put("1", "\"50411758798f11294a9c27de6c37b4e9\"");
//        partEtagMap.put("2", "\"900150983cd24fb0d6963f7d28e17f72\"");
//        partEtagMap.put("3", "\"50411758798f11294a9c27de6c37b4e9\"");
//        
//        OOSInterfaceTestUtils.Object_CompleteMultipartUpload("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","mulit4.txt", uploadId, partEtagMap);
//        
//        OOSInterfaceTestUtils.Object_Get("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","mulit4.txt");
//        OOSInterfaceTestUtils.Object_ListPart("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","mulit4.txt", uploadId);
//        OOSInterfaceTestUtils.Object_DeleteMulit("http", "V2", 80,accessKey, secretKey, "yx-bucket-2", Arrays.asList("mulit1.txt","mulit2.txt"));
//        OOSInterfaceTestUtils.Object_DeleteMulit("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2", Arrays.asList("mulit3.txt","mulit3.txt"));

//        OOSInterfaceTestUtils.Object_Post("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","post1.txt", "123");
//        OOSInterfaceTestUtils.Object_Get("http", "V2", 80,accessKey, secretKey, "yx-bucket-2","post1.txt");
//        OOSInterfaceTestUtils.Object_Post("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","post2.txt", "456");
//        OOSInterfaceTestUtils.Object_Get("http", "V4", 80,accessKey, secretKey, "yx-bucket-2","post2.txt");
//        OOSInterfaceTestUtils.Object_Post("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","post3.txt", "789");
//        OOSInterfaceTestUtils.Object_Get("https", "V2", 8444,accessKey, secretKey, "yx-bucket-2","post3.txt");
//        OOSInterfaceTestUtils.Object_Post("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2","post4.txt", "abc");
//        OOSInterfaceTestUtils.Object_Get("https", "V4", 8444,accessKey, secretKey, "yx-bucket-2","post4.txt");
    }

}
