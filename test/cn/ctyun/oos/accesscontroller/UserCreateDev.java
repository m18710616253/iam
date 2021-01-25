package cn.ctyun.oos.accesscontroller;

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
import org.junit.BeforeClass;
import org.junit.Test;

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
import common.tuple.Pair;

public class UserCreateDev {

    // 创建用户数量
    private static int createNumber = 1000;
    
    private static Log log = LogFactory.getLog(UserCreateDev.class);
    
    // 线程池
    private static ExecutorService executor = Executors.newFixedThreadPool(100);
    
    private static MetaClient metaClient = MetaClient.getGlobalClient();

    private static final OwnerMeta owner = new OwnerMeta("wangduo@ctyun.cn");
    private static final String accountId = owner.getAccountId();
    private static final String accessKey = "ak-wangduo";
    private static final String secretKey = "sk-wangduo";

    private static final String userName = "testUser";
    private static final String policyName = "testPolicy";
    private static final String groupName = "testGroup";


    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

        IAMTestUtils.TrancateTable("iam-user");
        IAMTestUtils.TrancateTable("iam-group");
        IAMTestUtils.TrancateTable("iam-policy");
        IAMTestUtils.TrancateTable("iam-accountSummary");
        
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

    }

    @Test
    public void createData() throws Exception {
        PrintWriter out = new PrintWriter(new FileWriter("users.txt"));

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
            Future<String> future = executor.submit(() -> {
                String uName = userName + "_" + num;
                try {
                    // 创建一个用户
                    createUser(uName);
                    AccessKeyResult accessKeyResult = createAccessKey(uName);
                    // 给奇数的用户附加策略
                    if (num % 2 == 1) {
                        attachUserPolicy(uName);
                    }
                    addUserToGroup(uName);
                    // 记录用户名和 ak
                    synchronized (out) {
                        out.println(uName + "," + accessKeyResult.accessKeyId + "," + accessKeyResult.secretAccessKey);
                    }
                } catch (Exception e) {
                    log.error("create user " + uName + " failed.", e);
                }
                return uName;
            });
            futures.add(future);
        }
        
        futures.forEach(f -> {
            try {
                System.out.println(f.get());
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        System.out.println(System.currentTimeMillis() - start);

        out.close();
    }

    /**
     * 创建用户
     * @param userName
     */
    private static void createUser(String userName) {
        
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
    private static AccessKeyResult createAccessKey(String userName) throws JDOMException, IOException {
        
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
    private static void attachUserPolicy(String userName) throws JDOMException, IOException {
        
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
    private static void addUserToGroup(String userName) throws JDOMException, IOException {
        
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
