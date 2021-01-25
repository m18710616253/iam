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
import java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy;
import java.util.concurrent.TimeUnit;

import cn.ctyun.oos.accesscontroller.UsersReaderDev.User;

public class UserRequestDev {

    
    private static int nThreads = 500;
    // 线程池
    private static ExecutorService executor = new ThreadPoolExecutor(nThreads, nThreads, 0L, TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(100), Executors.defaultThreadFactory(), new CallerRunsPolicy());
    
    public static void main(String[] args) throws FileNotFoundException, IOException {
        
        List<User> users = UsersReaderDev.getUsers();
        
        Random random = new Random();
        while (true) {
            int index = random.nextInt(users.size());
            User user = users.get(index);
            executor.submit(() -> {
                try {
                    URL url = new URL(OOSTestUtilsDev.OOS_IAM_DOMAIN);
                    HttpURLConnection connection = OOSTestUtilsDev.invokeHttpsRequest(url, "GET", user.accessKey, user.secretKey);
                    connection.connect();
                    int code = connection.getResponseCode();
//                    if (Integer.parseInt(user.userName.split("_")[1]) % 2 == 1) {
//                        assertEquals(200, code);
//                    } else {
//                        assertEquals(403, code);
//                    }
                    System.out.println("-----------------------------------------" + code);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                
            });
        }
    }
}
