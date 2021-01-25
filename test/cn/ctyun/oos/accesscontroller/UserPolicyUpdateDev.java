package cn.ctyun.oos.accesscontroller;

import static org.junit.Assert.assertEquals;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy;

import cn.ctyun.oos.accesscontroller.UsersReaderDev.User;
import cn.ctyun.oos.iam.test.iamaccesscontrol.IAMInterfaceTestUtils;
import cn.ctyun.oos.metadata.OwnerMeta;

public class UserPolicyUpdateDev {

    private static final OwnerMeta owner = new OwnerMeta("wangduo@ctyun.cn");
    private static final String accountId = owner.getAccountId();
    private static final String accessKey = "ak-wangduo";
    private static final String secretKey = "sk-wangduo";

    private static final String userName = "testUser";
    private static final String policyName = "testPolicy";
    private static final String groupName = "testGroup";
    
    // 线程池
    private static ExecutorService executor = new ThreadPoolExecutor(10, 10, 0L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(10), Executors.defaultThreadFactory(), new CallerRunsPolicy());
    
    public static void main(String[] args) throws FileNotFoundException, IOException {
        
        List<User> users = UsersReaderDev.getUsers();
        
        Random random = new Random();
        while (true) {
            int index = random.nextInt(users.size());
            User user = users.get(index);
            executor.submit(() -> {
                try {
//                    IAMInterfaceTestUtils.DetachUserPolicy(accessKey, secretKey, accountId, user.userName, policyName, 200);
//                    IAMInterfaceTestUtils.AttachUserPolicy(accessKey, secretKey, accountId, user.userName, policyName, 200);
//                    IAMInterfaceTestUtils.UpdateAccessKey(accessKey, secretKey, user.accessKey, user.userName, "Inactive", 200);
//                    IAMInterfaceTestUtils.UpdateAccessKey(accessKey, secretKey, user.accessKey, user.userName, "Active", 200);
                    IAMInterfaceTestUtils.DeleteAccessKey(accessKey, secretKey, user.accessKey, user.userName, 200);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                
            });
        }
    }
}
