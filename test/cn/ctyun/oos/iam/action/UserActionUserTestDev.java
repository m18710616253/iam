package cn.ctyun.oos.iam.action;

import java.io.IOException;

import org.junit.Test;

import cn.ctyun.oos.iam.server.action.api.AccessKeyAction;
import cn.ctyun.oos.iam.server.param.CreateAccessKeyParam;
import cn.ctyun.oos.iam.server.result.CreateAccessKeyResult;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.util.IAMHttpTestClient;
import common.tuple.Pair;

/**
 * 子用户
 * @author wangduo
 *
 */
public class UserActionUserTestDev {

    // userwd
//    public static final String accessKey="92558668ca7fd4196e40";
//    public static final String secretKey="d9df6c4adda4a5f2ae559904e8e174d2ba49ad42";

    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";
    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);
    public static  String userName="changePasswordUser6";
    
    @Test
    public void createUserAndAk() throws Exception {
        
        String body="Action=CreateUser&Version=2010-05-08&UserName="+userName;
        String xml = httpTestClient.post(body);
        System.out.println(xml);
        
        body="Action=CreateLoginProfile&UserName="+userName+"&Password=a12345678";
        xml = httpTestClient.post(body);
        System.out.println(xml);
        
        body="Action=CreateAccessKey&UserName="+userName;
        xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testChangePassword() throws Exception {

        String ak = "469da17b0ad276dfd6a3";
        String sk = "16f943a0ddcd1009b51ff650a6d6429fdc90a6ac";
        
        String oldp = "a12345678";
        String newp = "a123456781455";
        
        String body="Action=ChangePassword&UserName="+userName+"&OldPassword=" + oldp + "&NewPassword=" + newp;
        Pair<Integer, String> changePasswd=IAMTestUtils.invokeHttpsRequest(body, ak, sk);
        
    }
    
}
