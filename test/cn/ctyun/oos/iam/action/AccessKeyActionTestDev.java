/**
 * 
 */
package cn.ctyun.oos.iam.action;

import java.net.HttpURLConnection;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.test.IAMTestUtils;
import cn.ctyun.oos.iam.test.oosaccesscontrol.OOSInterfaceTestUtils;
import cn.ctyun.oos.iam.util.IAMHttpTestClient;
import cn.ctyun.oos.metadata.AkSkMeta;
import common.tuple.Pair;

/**
 * @author wangduo
 *
 */
public class AccessKeyActionTestDev {

    // userwd
    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";

    // 新
//  public static final String accessKey="21d171347031ab2c8123";
//  public static final String secretKey="58877886ec41c3188118e8e732b40667b4b0e8ac";
    
  // 旧
//  public static final String accessKey="d58fca87250543778e4d";
//  public static final String secretKey="52e82985b290726fc6c7b1bed497cef38f0e2fad";
  
    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);

    @Test
    public void testCreateAccessKey() throws Exception {
        String body="Action=CreateAccessKey&Version=2010-05-08";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testUpdateAccessKey() throws Exception {
        String body="Action=UpdateAccessKey&Version=2010-05-08&AccessKeyId=d58fca87250543778e4d&IsPrimary=true";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testDeleteAccessKey() throws Exception {
        String body="Action=DeleteAccessKey&AccessKeyId=e6eecf33c8cb0c3f7c3c";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testListAccessKeys() throws Exception {
        String body="Action=ListAccessKeys&Version=2010-05-08";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testListAccessKey() throws Exception {
        String body="Action=ListAccessKey&Version=2010-05-08";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testGetUser() throws Exception {
        String body="Action=GetUser";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
  
    
    @Test
    /*
     * list 根用户ak
     */
    public void test_listAccessKeys_Root() throws Exception{
        
        MetaClient metaClient = MetaClient.getGlobalClient();
        AkSkMeta aksk = new AkSkMeta(5774479117803632717L);
//        aksk.accessKey="userak4";
//        aksk.setSecretKey("usersk2");
//        aksk.isPrimary=1;
//        metaClient.akskInsert(aksk);
        aksk.accessKey="userak6";
        aksk.setSecretKey("usersk3");
        aksk.isPrimary=0;
        metaClient.akskInsert(aksk);
        
        String body="Action=ListAccessKeys";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
    @Test
    public void test_createAccessKey() {
        String body="Action=CreateAccessKey";
        Pair<Integer, String> resultPair=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
    @Test
    public void test_deleteAccessKey_User_rootAk() {
        String body="Action=DeleteAccessKey&AccessKeyId="+"25a5e92ccadc3b7442cd";
        //String body="Action=DeleteAccessKey&AccessKeyId="+"";
        Pair<Integer, String> delete=IAMTestUtils.invokeHttpsRequest(body, accessKey, secretKey);
    }
    
    
    @Test
    public void testServiceGet() {
        OOSInterfaceTestUtils.Service_Get("http", "V4", 8080, accessKey, secretKey, null);
    }
    
    @Test
    public void listAccessKeysV2() throws Exception {
        String urlStr = "https://oos-cd-iam.ctyunapi.cn:9460/?Action=ListAccessKeys";

        HttpURLConnection conn=OOSInterfaceTestUtils.CreateConn(urlStr, "https", "V2", accessKey, secretKey, "GET", null, null, null, null, null, 80);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Host", "oos-cd-iam.ctyunapi.cn:9460");
        int code = conn.getResponseCode();
        String xml ="";
        if (code==200) {
            xml = IOUtils.toString(conn.getInputStream());
        }else {
            xml = IOUtils.toString(conn.getErrorStream());
        }
        System.out.println(xml);
    }
    
    
}
