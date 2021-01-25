package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;

/**
 * STS授权请求参数
 * @author wangduo
 *
 */
public class GetSessionTokenParam extends ActionParameter {

    public Integer durationSeconds;
    
    @Override
    public void validate() {
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateUserArn(getAccountId(), "*");
    }
    
}
