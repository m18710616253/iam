package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.server.action.ActionParameter;

/**
 * 获取IAM的实体使用和配额信息请求参数
 * @author wangduo
 *
 */
public class GetAccountSummaryParam extends ActionParameter {
    
    @Override
    public void validate() {
    }
    
    @Override
    public String toJson() {
        return null;
    }
}
