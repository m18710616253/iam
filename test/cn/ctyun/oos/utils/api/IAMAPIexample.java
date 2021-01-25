package cn.ctyun.oos.utils.api;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import common.tuple.Pair;

public class IAMAPIexample {
    String endpointUrlStr="https://oos-cd-iam.ctyunapi.cn:9460/";
    String regionName="cd";
//    String accessKey="d5486d49a20339f164a5";
//    String secretKey="adf5f77f00e9dc5d39da406d00005e45e68b8b3d";
    public static final String accessKey="userak1";
    public static final String secretKey="usersk1";;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void test() {
        String body="Action=GetAccountSummary";
        Pair<Integer, String> result=IAMAPITestUtils.IAMRequest(endpointUrlStr, regionName, accessKey, secretKey, body,null);
        assertEquals(200, result.first().intValue());
        System.out.println(result.second());
    }

}
