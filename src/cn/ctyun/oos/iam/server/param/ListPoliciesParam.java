package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 列出账户中可用的所有策略参数
 * @author wangduo
 *
 */
public class ListPoliciesParam extends ActionParameter {

    public String scope;
    public Boolean onlyAttached;
    public String marker;
    public Integer maxItems = 100;
    public String policyName;
    
    @Override
    public void validate() {
        
        if (scope !=null && PolicyScopeType.fromValue(scope) == null) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyScopeInvalid", 
                    "Value '" + scope + "' at 'scope' failed to satisfy constraint: Member must satisfy enum value set: [All, Local, OOS]");
            errorMessages.add(errorMessage);
        }
        ValidationUtils.validateMarker(marker, errorMessages);
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
        if (policyName != null) {
            ValidationUtils.validatePolicyName(policyName, errorMessages);
        }
    }
    
    public boolean isOnlyAttached() {
        return Boolean.TRUE.equals(onlyAttached);
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generatePolicyArn(getAccountId(), "*");
    }
}
