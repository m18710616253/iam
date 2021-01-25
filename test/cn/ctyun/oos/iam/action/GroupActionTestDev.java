/**
 * 
 */
package cn.ctyun.oos.iam.action;

import java.net.URLEncoder;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.oos.iam.util.IAMHttpTestClient;

/**
 * @author wangduo
 *
 */
public class GroupActionTestDev {

    public static final String accessKey="test_user8_6463084869102845087@a.cn88";
    public static final String secretKey="secretKey88";

    public static IAMHttpTestClient httpTestClient = new IAMHttpTestClient(accessKey, secretKey);

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

//    @Test
//    public void testAddUserToGroup() throws Exception {
//        String body="Action=AddUserToGroup&GroupName=wangsiyuGroup&UserName=user666&Version=2010-05-08";
//        String xml = httpTestClient.post(body);
//        System.out.println(xml);
//    }
    
    @Test
    public void testCreateGroup() throws Exception {
        String body="Action=CreateGroup&GroupName=test12313&Version=2010-05-08";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
    public void testGetGroup() throws Exception {
        String body="Action=GetGroup&GroupName=" + URLEncoder.encode("test1234") + "&Version=2010-05-08";
        String xml = httpTestClient.post(body);
        System.out.println(xml);
    }
    
    @Test
  public void testListGroups() throws Exception {
      String body="Action=ListGroups&Version=2010-05-08";
      String xml = httpTestClient.post(body);
      System.out.println(xml);
  }
    

    
}
