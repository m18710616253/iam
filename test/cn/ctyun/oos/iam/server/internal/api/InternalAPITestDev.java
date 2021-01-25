package cn.ctyun.oos.iam.server.internal.api;

import org.junit.Test;

import cn.ctyun.oos.metadata.OwnerMeta;

public class InternalAPITestDev {

    @Test
    public void testLogin() throws Exception {
        OwnerMeta owner = new OwnerMeta("test_user8_6463084869102845087@a.cn");
        
        LoginParam loginParam = new LoginParam();
        loginParam.accountId = owner.getAccountId();
        loginParam.userName = "testUser111";
        loginParam.passwordMd5 = "12345678a@Q";
        loginParam.loginIp = "123.123.123.123";
        
        LoginResult loginResult = IAMInternalAPI.login(loginParam);
        
        System.out.println(loginResult.accessKeyId);
        System.out.println(loginResult.secretAccessKey);
        System.out.println(loginResult.iPLastUsed);
        System.out.println(loginResult.passwordLastUsed);
    }

}
