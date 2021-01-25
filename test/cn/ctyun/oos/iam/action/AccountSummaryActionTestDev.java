/**
 * 
 */
package cn.ctyun.oos.iam.action;

import org.junit.Test;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.util.IAMHttpTestClient;
import cn.ctyun.oos.metadata.AkSkMeta;
import common.tuple.Pair;

/**
 * @author wangduo
 *
 */
public class AccountSummaryActionTestDev {

    // userwd
    public static final String accessKey="d9866d49a20339f164a5";
    public static final String secretKey="adf5f37900e9dc5d39da406d00005e45e68b8b3d";

    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);

    @Test
    public void testGetAccountSummary() throws Exception {
        String body="Action=GetAccountSummary&Version=2010-05-08";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    

}
