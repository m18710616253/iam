package cn.ctyun.oos.iam.action;

import org.junit.Before;
import org.junit.Test;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;

public class DataInitDev {

    private static MetaClient metaClient = MetaClient.getGlobalClient();
    private String ownerName1 = "test_user8_6463084869102845087@a.cn";
    private OwnerMeta owner1 = new OwnerMeta(ownerName1);
    
    @Before
    public void before() throws Exception {
        IAMTestUtils.TrancateTable("oos-aksk");
        IAMTestUtils.TrancateTable("oos-owner");
        
        // 创建user
        owner1.verify = null;
        owner1.currentAKNum = 0;
        owner1.maxAKNum = 10;
        owner1.proxyLastLoginTime = System.currentTimeMillis();
        owner1.proxyLastLoginIp = "192.168.0.1";
        metaClient.ownerDelete(owner1);
        metaClient.ownerInsertForTest(owner1);
        metaClient.ownerSelect(owner1);
        
        AkSkMeta asKey = new AkSkMeta(owner1.getId());
        asKey.setSecretKey("secretKey88");
        asKey.accessKey = ownerName1 + "88";
        asKey.status = 1;
        asKey.isPrimary = 1;
        metaClient.akskInsert(asKey);
    }
    
    @Test
    public void testAuth() {
    }

}
