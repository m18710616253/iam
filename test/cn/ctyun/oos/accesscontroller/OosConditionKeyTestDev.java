package cn.ctyun.oos.accesscontroller;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.amazonaws.auth.SigningAlgorithm;
import com.amazonaws.services.s3.internal.RestUtils;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseUserToTag;
import cn.ctyun.oos.hbase.HBaseVSNTag;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.signer.OOSRequest;
import cn.ctyun.oos.iam.test.HttpsRequestUtils;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.V4TestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.iam.test.oosaccesscontrol.OOSInterfaceTestUtils;
import cn.ctyun.oos.iam.test.oosaccesscontrol.PreUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import common.time.TimeUtils;
import common.tuple.Pair;

public class OosConditionKeyTestDev {

    static String HOST="oos-cd.ctyunapi.cn";
    
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    public static final String regionName="cd";
    
    public static final int jettyHttpPort=8080;
    public static final int jettyHttpsPort=8443;
    
    public static final String httpOrHttps="http";
    public static final int jettyport=jettyHttpPort;
    
    public static final String signVersion="V4";
    
    
    public static final String bucketName="wd-bucket";
    
    
    private static String ownerName = "root_user@test.com";
    public static final String accessKey="userak";
    public static final String secretKey="usersk";
    
    public static final String user1Name="test_1";
    public static final String user2Name="test_2";
    public static final String user3Name="Abc1";
    public static final String user1accessKey1="abcdefghijklmnop";
    public static final String user1secretKey1="cccccccccccccccc";
    
    public static String accountId="3rmoqzn03g6ga";
    public static String mygroupName="mygroup";
    
    
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();
    static Configuration globalConf = GlobalHHZConfig.getConfig();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        IAMTestUtils.TrancateTable("oos-aksk");
        IAMTestUtils.TrancateTable("iam-user");
        IAMTestUtils.TrancateTable(IAMTestUtils.iamAccountSummaryTable);
        
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
        
        
        String UserName1=user1Name;
        User user1=new User();
        user1.accountId=accountId;
        user1.userName=UserName1;
        user1.userId="test1abc";
        user1.createDate=System.currentTimeMillis();
        try {
            boolean success=HBaseUtils.checkAndCreate(user1);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 插入数据库aksk
        AkSkMeta aksk1 = new AkSkMeta(owner.getId());
        aksk1.isRoot = 0;
        aksk1.userId = user1.userId;
        aksk1.userName = UserName1;
        aksk1.accessKey=user1accessKey1;
        aksk1.setSecretKey(user1secretKey1);
        metaClient.akskInsert(aksk1);
        user1.accessKeys = new ArrayList<>();
        user1.accessKeys.add(aksk1.accessKey);
        HBaseUtils.put(user1);
        
        HBaseAdmin globalHbaseAdmin = new HBaseAdmin(globalConf);
        
        HBaseUserToTag.dropTable(GlobalHHZConfig.getConfig());
        HBaseUserToTag.createTable(globalHbaseAdmin);
        HBaseVSNTag.dropTable(GlobalHHZConfig.getConfig());
        HBaseVSNTag.createTable(globalHbaseAdmin);
        Thread.sleep(1000);
        
        VSNTagMeta dataTag1;
        VSNTagMeta metaTag1;
        
        
        dataTag1 = new VSNTagMeta("tag1", Arrays.asList(new String[] { "huabei"}), VSNTagType.DATA);
        metaClient.vsnTagInsert(dataTag1);
        metaTag1 = new VSNTagMeta("mtag1", Arrays.asList(new String[] { "huabei" }), VSNTagType.META);
        metaClient.vsnTagInsert(metaTag1);
        
        UserToTagMeta user2Tag1 = new UserToTagMeta(owner.getId(),
                Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
        metaClient.userToTagInsert(user2Tag1);
        UserToTagMeta user2Tag2 = new UserToTagMeta(owner.getId(),
                Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
        metaClient.userToTagInsert(user2Tag2);
        
    }

    @Before
    public void setUp() throws Exception {
        // 清空iam-policy表
        // iam-user表中去掉policy关联
        IAMTestUtils.TrancateTable(IAMTestUtils.iamPolicyTable);
        IAMTestUtils.TrancateTable("oos-bucket");
        IAMTestUtils.UpdateUserTable("policy","policyCount");
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null, null, null, null, params);
    }

    @Test
    public void testListBucketWithPrefix() throws Exception  {
        
        Pair<Integer, String> pair;
        
        // 没有策略，不通过 
        pair = Bucket_GetPrefix(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, user1Name + "/1234", bucketName, null);
        assertEquals(403, pair.first().intValue());
        
        // 附加策略
        String policyName="iamPolicy";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringLike","oos:prefix",Arrays.asList("${ctyun:username}/*")));
        String oosPolicy=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName), conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, oosPolicy, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // oos条件键不匹配，不通过
        pair = Bucket_GetPrefix(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, "1234", bucketName, null);
        assertEquals(403, pair.first().intValue());
        
        // 有oos条件键通过
        pair = Bucket_GetPrefix(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, user1Name + "/1234", bucketName, null);
        assertEquals(200, pair.first().intValue());
        
        // 对于 oos:* 其他请求可以正常通过
        pair = OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(200, pair.first().intValue());
        
    }
    
    @Test
    public void testPutBucketWithAcl() throws Exception  {
        
        Pair<Integer, String> pair;
        
        pair = OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null, null, null, null, null);
        assertEquals(403, pair.first().intValue());
        
        // 附加策略
        String policyName="aclPolicy";
        List<Condition> conditions = new ArrayList<Condition>();
        conditions.add(IAMTestUtils.CreateCondition("StringEquals","oos:x-amz-acl",Arrays.asList("private")));
        String oosPolicy=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:*"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":"+bucketName), conditions);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, oosPolicy, 200);
        IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user1Name, policyName, 200);
        
        // oos条件键不匹配，不通过
        pair = OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null, null, null, null, null);
        assertEquals(403, pair.first().intValue());
        
        // 有oos条件键通过
        HashMap<String, String> params=new HashMap<String, String>();
        params.put("x-amz-acl", "private");
        pair = OOSInterfaceTestUtils.Bucket_Put(httpOrHttps, signVersion, jettyport, accessKey, secretKey, bucketName, null, null, null, null, params);
        assertEquals(200, pair.first().intValue());
        
        // 对于 oos:* 其他请求可以正常通过
        pair = OOSInterfaceTestUtils.Bucket_GetAcl(httpOrHttps, signVersion, jettyport, user1accessKey1, user1secretKey1, bucketName, null);
        assertEquals(200, pair.first().intValue());
        
    }
    
    /*
     * list object
     */
    public static Pair<Integer, String> Bucket_GetPrefix(String httpOrHttps,String signVersion,int jettyPort,String accessKey,String secretKey, String prefix, String bucketName,HashMap<String, String> headers) {
        String urlStr=httpOrHttps+"://"+HOST+":"+jettyPort+"/"+bucketName+"/?prefix="+prefix;
        String method="GET";
        Map<String, String> querys=new HashMap<String, String>();
        querys.put("prefix", prefix);
        
        HttpURLConnection conn=null;
        try {
            String canonicalString="";
            URL url = new URL(urlStr);
            if (headers==null) {
                headers = new HashMap<String, String>();
            }
            
            if (signVersion.equals("V4")) {
                System.out.println("V4");
                
                String authorization = V4TestUtils.computeSignature(headers, querys, UNSIGNED_PAYLOAD, accessKey, secretKey, 
                        url, method, "s3", regionName);
                headers.put("Authorization", authorization);
                if (httpOrHttps.equals("https")) {
                    conn=HttpsRequestUtils.createConn(url, method, headers);
                    System.out.println(" url="+url.toString());
                }else {
                    conn=OOSInterfaceTestUtils.CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
            }else if (signVersion.startsWith("Pre")) {
                if("https".equals(httpOrHttps)) {
                    conn = PreUtils.getPreUrlHttpsConn(bucketName, null, method, accessKey, secretKey, querys, headers,signVersion,HOST,jettyPort);
                }else {
                    conn = PreUtils.getPreUrlHttpConn(bucketName, null, method, accessKey, secretKey, querys, headers,signVersion,HOST,jettyPort);
                }
            }else {
                System.out.println("V2");
                String date = TimeUtils.toGMTFormat(new Date());
                headers.put("Date", date);
                if (httpOrHttps.equals("https")) {
                    conn=HttpsRequestUtils.createConn(url, method, headers);
                    System.out.println("url="+url.toString());
                    
                }else {
                    conn=OOSInterfaceTestUtils.CreatehttpConn(url, method, headers);
                    System.out.println("url="+url.toString());
                }
                
                if (headers != null) {
                    for (String headerKey : headers.keySet()) {
                        conn.setRequestProperty(headerKey, headers.get(headerKey));
                    }
                }
                canonicalString = RestUtils.makeS3CanonicalString(method, 
                        OOSInterfaceTestUtils.toResourcePath(bucketName, null, true), new OOSRequest<>(conn), null);
                System.out.println("canonicalString=\r\n"+canonicalString);
                String signature = OOSInterfaceTestUtils.sign(canonicalString, secretKey, SigningAlgorithm.HmacSHA1);
                String authorization = "AWS " + accessKey + ":" + signature;
                conn.setRequestProperty("Authorization", authorization);  
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return OOSInterfaceTestUtils.GetResult(conn);
        
    }
    
}
