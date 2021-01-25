package cn.ctyun.oos.iam.test.oosaccesscontrol;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.util.UrlEncoded;
import org.jdom.JDOMException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;

import cn.ctyun.oos.accesscontroller.UserCreateDev;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.AccessKeyResultUtilsDev;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.result.AccessKeyResult;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.UserToTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta;
import cn.ctyun.oos.metadata.VSNTagMeta.VSNTagType;
import cn.ctyun.oos.utils.api.OOSAPITestUtils;
import common.tuple.Pair;
import common.util.BlockingExecutor;

public class OOSCahce10wTest {
    
    String OOS_DOMAIN="http://oos-cd.ctyunapi.cn/";
    private static Log log = LogFactory.getLog(OOSCahce10wTest.class);

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void create10wUser1() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(500);
        
        MetaClient metaClient = MetaClient.getGlobalClient();

        OwnerMeta owner = new OwnerMeta("root_user1@test.com");
        String accountId = owner.getAccountId();
        String accessKey = "userak1";
        String secretKey = "usersk1";

        String userName = "testUser";
        String policyName = "testPolicy";
        String groupName = "testGroup";
        
        int createNumber=15000;
        
        IAMTestUtils.TrancateTable("iam-user-yx");
        IAMTestUtils.TrancateTable("iam-group-yx");
        IAMTestUtils.TrancateTable("iam-policy-yx");
        IAMTestUtils.TrancateTable("iam-accountSummary-yx");

        // 创建owner
        owner.verify = null;
        owner.currentAKNum = 0;
        owner.maxAKNum = 2;
        metaClient.ownerInsertForTest(owner);
        metaClient.ownerSelect(owner);

        AkSkMeta asKey = new AkSkMeta(owner.getId());
        asKey.accessKey = accessKey;
        asKey.setSecretKey(secretKey);
        asKey.status = 1;
        asKey.isPrimary = 1;
        metaClient.akskInsert(asKey);
        
        // 设置限额
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(accountId);
        accountSummary.usersQuota = Long.MAX_VALUE;
        accountSummary.groupsQuota = Long.MAX_VALUE;
        accountSummary.policiesQuota = Long.MAX_VALUE;
        AccountSummaryService.putAccountQuota(accountSummary);
        
        
        PrintWriter out = new PrintWriter(new FileWriter("D:\\test\\users.txt"));

        // 创建策略
        String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
        IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, policyName, policyString,200);
        // 创建组
        String createGroupBody = "Action=CreateGroup&Version=2010-05-08&GroupName=" + groupName;
        IAMTestUtils.invokeHttpsRequest(createGroupBody, accessKey, secretKey);
        
        long start = System.currentTimeMillis();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 1; i <= createNumber; i++) {
            final int num = i;
            // 多线程创建子用户、子用户AK、添加组、附加策略
            Future<?> future = executor.submit(() -> {
                String uName = userName + "_" + num;
                try {
                    // 创建一个用户
                    createUser(accessKey, secretKey, uName);
                    AccessKeyResult accessKeyResult = createAccessKey(accessKey,secretKey,uName);
                    if (num % 2 == 1) {
                        attachUserPolicy(accessKey, secretKey, accountId, uName, policyName);
                    }
                    addUserToGroup(accessKey, secretKey, groupName, uName);
                    // 记录用户名和 ak
                    synchronized (out) {
                        out.println(uName + "," + accessKeyResult.accessKeyId + "," + accessKeyResult.secretAccessKey);
                    }
                } catch (Exception e) {
                    log.error("create user " + uName + " failed.", e);
                }
            });
            futures.add(future);
        }
        
        futures.forEach(f -> {
            try {
                f.get();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        System.out.println(System.currentTimeMillis() - start);

        out.close();
    }
    
    
    
    @Test
    public void create10wUser2() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(500);
        MetaClient metaClient = MetaClient.getGlobalClient();

        String userName = "testUser";
        String policyName = "testPolicy";
        String groupName = "testGroup";
        
        int createNumber=500;
        
        IAMTestUtils.TrancateTable("iam-user-yx");
        IAMTestUtils.TrancateTable("iam-group-yx");
        IAMTestUtils.TrancateTable("iam-policy-yx");
        IAMTestUtils.TrancateTable("iam-accountSummary-yx");
        
        PrintWriter out = new PrintWriter(new FileWriter("D:\\test\\users2.txt"));
        
        int accountNum=30;
        long start = System.currentTimeMillis();
        
        // 创建根用户
        for (int j = 0; j < accountNum; j++) {
            OwnerMeta owner = new OwnerMeta("root_user"+(j+1)+"@test.com");
            String accountId = owner.getAccountId();
            String accessKey = "userak"+(j+1);
            String secretKey = "usersk"+(j+1);
            
         // 创建owner
            owner.verify = null;
            owner.currentAKNum = 0;
            owner.maxAKNum = 2;
            metaClient.ownerInsertForTest(owner);
            metaClient.ownerSelect(owner);

            AkSkMeta asKey = new AkSkMeta(owner.getId());
            asKey.accessKey = accessKey;
            asKey.setSecretKey(secretKey);
            asKey.status = 1;
            asKey.isPrimary = 1;
            metaClient.akskInsert(asKey);
            
            // 设置限额
            AccountSummary accountSummary = AccountSummaryService.getAccountSummary(accountId);
            accountSummary.usersQuota = Long.MAX_VALUE;
            accountSummary.groupsQuota = Long.MAX_VALUE;
            accountSummary.policiesQuota = Long.MAX_VALUE;
            AccountSummaryService.putAccountQuota(accountSummary);
            
            VSNTagMeta dataTag1;
            VSNTagMeta metaTag1;
            
            
            dataTag1 = new VSNTagMeta("tag1", Arrays.asList(new String[] { "yxregion1","yxregion2"}), VSNTagType.DATA);
            metaClient.vsnTagInsert(dataTag1);
            metaTag1 = new VSNTagMeta("mtag1", Arrays.asList(new String[] { "yxregion1" }), VSNTagType.META);
            metaClient.vsnTagInsert(metaTag1);
            
            UserToTagMeta user2Tag1 = new UserToTagMeta(owner.getId(),
                    Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
            metaClient.userToTagInsert(user2Tag1);
            UserToTagMeta user2Tag2 = new UserToTagMeta(owner.getId(),
                    Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
            metaClient.userToTagInsert(user2Tag2);
            
            // 创建策略
            String policyString=IAMTestUtils.CreateOneStatementPolicyString(Effect.Allow,null,null,"Action",Arrays.asList("oos:ListAllMyBucket"),"Resource",Arrays.asList("arn:ctyun:oos::"+accountId+":*"),null);
            IAMInterfaceTestUtils.CreatePolicy(accessKey, secretKey, accountId+"_"+policyName, policyString,200);
            // 创建组
            String createGroupBody = "Action=CreateGroup&Version=2010-05-08&GroupName=" + accountId+"_"+groupName;
            IAMTestUtils.invokeHttpsRequest(createGroupBody, accessKey, secretKey);
            
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 1; i <= createNumber; i++) {
                final int num = i;
                Future<?> future = executor.submit(() -> {
            String uName = accountId+"_"+userName + "_" + num;
            try {
                // 创建一个用户
                createUser(accessKey, secretKey, uName);
                AccessKeyResult accessKeyResult = createAccessKey(accessKey,secretKey,uName);
                if (num % 2 == 1) {
                    attachUserPolicy(accessKey, secretKey, accountId, uName, accountId+"_"+policyName);
                }
                
                addUserToGroup(accessKey, secretKey, accountId+"_"+groupName, uName);
                // 记录用户名和 ak
                synchronized (out) {
                    out.println(uName + "," + accessKeyResult.accessKeyId + "," + accessKeyResult.secretAccessKey);
                }
            } catch (Exception e) {
                log.error("create user " + uName + " failed.", e);
            }
            
                });
                futures.add(future);
            }
            
            futures.forEach(f -> {
                try {
                    f.get();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            
        }
        
        long end = System.currentTimeMillis();
        
        System.out.println(end-start); 
        
        out.close();

        
    }
    
    @Test
    public void test_addBucket() throws IOException {
        OwnerMeta owner = new OwnerMeta("root_user1@test.com");
        MetaClient metaClient = MetaClient.getGlobalClient();
        
        String accessKey = "userak1";
        String secretKey = "usersk1";
        
        VSNTagMeta dataTag1;
        VSNTagMeta metaTag1;
        
        
        dataTag1 = new VSNTagMeta("tag1", Arrays.asList(new String[] { "yxregion1","yxregion2"}), VSNTagType.DATA);
        metaClient.vsnTagInsert(dataTag1);
        metaTag1 = new VSNTagMeta("mtag1", Arrays.asList(new String[] { "yxregion1" }), VSNTagType.META);
        metaClient.vsnTagInsert(metaTag1);
        
        UserToTagMeta user2Tag1 = new UserToTagMeta(owner.getId(),
                Arrays.asList(new String[] { dataTag1.getTagName() }), VSNTagType.DATA);
        metaClient.userToTagInsert(user2Tag1);
        UserToTagMeta user2Tag2 = new UserToTagMeta(owner.getId(),
                Arrays.asList(new String[] { metaTag1.getTagName() }), VSNTagType.META);
        metaClient.userToTagInsert(user2Tag2);
        
        Pair<Integer, String> putbucket=OOSAPITestUtils.Bucket_Put("http", "oos-cd.ctyunapi.cn", 80, "V2", "cd", accessKey, secretKey, "yx-bucket-1", "Local", null, null, null, null);
        assertEquals(200, putbucket.first().intValue());
    }
    
    @Test
    public void runClient() throws IOException {
        long start = System.currentTimeMillis();
        List<AmazonS3> clients=CreateClient("D:\\test\\users.txt");
        
        System.out.println(System.currentTimeMillis() - start);
        System.err.println("clients size ="+clients.size());
        
        System.out.println();
        File file=new File("D:\\test\\client_in.txt");
        ExecutorService executor = Executors.newFixedThreadPool(2000);
        List<Future<?>> futures = new ArrayList<>();

            // 多线程创建子用户、子用户AK、添加组、附加策略
            Future<?> future = executor.submit(() -> {
                for (int i = 0; i < clients.size(); i++) {
                    try {
                        clients.get(i).listBuckets();
//                        clients.get(i).putObject("yx-bucket-1", "object"+i, file);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    
                }
                
            });
            futures.add(future);
        
        futures.forEach(f -> {
            try {
                f.get();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        System.out.println(System.currentTimeMillis() - start);
    }
    
    public List<AmazonS3> CreateClient(String filepath) throws IOException {
        List<AmazonS3> clients= new ArrayList<AmazonS3>();
        
        FileReader fr=new FileReader(filepath);
        BufferedReader br=new BufferedReader(fr);
        String line="";
        String[] arrs=null;
        while ((line=br.readLine())!=null) {
            arrs=line.split(",");
            System.out.println(arrs[0] + " : " + arrs[1] + " : " + arrs[2]);
            String ak=arrs[1];
            String sk=arrs[2];
            AmazonS3 client=new AmazonS3Client(new AWSCredentials() {
                @Override
                public String getAWSSecretKey() {
                    return sk;
                }

                @Override
                public String getAWSAccessKeyId() {
                    return ak;
                }
            });
            client.setEndpoint(OOS_DOMAIN);
            clients.add(client);
        }
        br.close();
        fr.close();
        
        System.out.println(clients.size());
        return clients;
    }
    
    /**
     * 创建用户
     * @param userName
     */
    private static void createUser(String accessKey,String secretKey,String userName) {
        
        for (int i = 0; i < 5; i++) {
            String createUserBody = "Action=CreateUser&Version=2010-05-08&UserName=" + userName;
            Pair<Integer, String> createUserResult = IAMTestUtils.invokeHttpsRequest(createUserBody, accessKey, secretKey);
            // 成功不进行重试
            if (createUserResult.first() == 200) {
                return;
            }
        }
        throw new RuntimeException("createAccessKey failed, userName : " + userName);
    }
    
    /**
     * 创建AK
     * @param userName
     * @return
     * @throws JDOMException
     * @throws IOException
     */
    private static AccessKeyResult createAccessKey(String accessKey,String secretKey,String userName) throws JDOMException, IOException {
        
        for (int i = 0; i < 5; i++) {
            String createUserBody = "Action=CreateAccessKey&Version=2010-05-08&UserName=" + userName;
            Pair<Integer, String> createAccessKeyResult = IAMTestUtils.invokeHttpsRequest(createUserBody, accessKey, secretKey);
            // 成功不进行重试
            if (createAccessKeyResult.first() == 200) {
                return AccessKeyResultUtilsDev.convertToAccessKeyResult(createAccessKeyResult.second());
            }
        }
        throw new RuntimeException("createAccessKey failed, userName : " + userName);
    }

    
    /**
     * 附加策略
     * @param userName
     * @return
     * @throws JDOMException
     * @throws IOException
     */
    private static void attachUserPolicy(String accessKey,String secretKey, String accountId,String userName,String policyName) throws JDOMException, IOException {
        
        for (int i = 0; i < 5; i++) {
            String policyArn="arn:ctyun:iam::"+accountId+":policy/"+policyName;
            String body="Action=AttachUserPolicy&Version=2010-05-08&UserName="+ UrlEncoded.encodeString(userName) +"&PolicyArn="+UrlEncoded.encodeString(policyArn);
            Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
            // 成功不进行重试
            if (result.first() == 200) {
                return;
            }
        }
        throw new RuntimeException("attachUserPolicy failed, userName : " + userName);
    }
    
    /**
     * 添加到组
     * @param userName
     * @return
     * @throws JDOMException
     * @throws IOException
     */
    private static void addUserToGroup(String accessKey,String secretKey, String groupName,String userName) throws JDOMException, IOException {
        
        for (int i = 0; i < 5; i++) {
            String body="Action=AddUserToGroup&Version=2010-05-08&GroupName="+UrlEncoded.encodeString(groupName)+"&UserName="+UrlEncoded.encodeString(userName);
            Pair<Integer, String> result = IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
            // 成功不进行重试
            if (result.first() == 200) {
                return;
            }
        }
        throw new RuntimeException("addUserToGroup failed, userName : " + userName);
    }

}
