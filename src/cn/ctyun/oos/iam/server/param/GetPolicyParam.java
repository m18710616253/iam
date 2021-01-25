package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 获取策略请求参数
 * @author wangduo
 *
 */
public class GetPolicyParam extends ActionParameter {

    public String policyArn;
    
    /**
     * 参数校验
     */
    @Override
    public void validate() {
        // 校验策略ARN
       ValidationUtils.validatePolicyArn(policyArn, errorMessages);
    }

    public String getResource() {
        return policyArn;
    }
    
    @Override
    public String getResourceArn() {
        return policyArn;
    }
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generatePolicyResources(policyArn));
        return resources;
    }
}
