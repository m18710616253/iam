package cn.ctyun.oos.iam.server.param;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.action.api.AccessKeyAction;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.AkSkMeta;

/**
 * 检索有关上次使用指定访问密钥的时间的信息
 * @author wangduo
 *
 */
public class GetAccessKeyLastUsedParam extends ActionParameter {

    private static final Log log = LogFactory.getLog(AccessKeyAction.class);
    
    public String accessKeyId;
    
    @Override
    public void validate() {
        ValidationUtils.validateAccessKeyId(accessKeyId, errorMessages);
    }

    public String getResource() {
        return accessKeyId;
    }
    
    @Override
    public String getResourceArn() {
        // AK的用户名
        String userName = "";
        // 获取AK
        AkSkMeta accessKey = new AkSkMeta(accessKeyId);
        try {
            MetaClient.getGlobalClient().akskSelect(accessKey);
            if (accessKey.userName != null) {
                userName = accessKey.userName;
            }
        } catch (IOException e) {
            log.error("get accessKey failed, accessKeyId: " + accessKeyId, e);
        }
        return ARNUtils.generateUserArn(getAccountId(), userName);
    }

    @Override
    public String getResourceTip() {
        return "access key " + accessKeyId;
    }
}
