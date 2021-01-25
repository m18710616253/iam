package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.entity.PolicyEntity;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 列出指定托管策略所附加的所有IAM用户和组参数
 * @author wangduo
 *
 */
public class ListEntitiesForPolicyParam extends ActionParameter {

    public String policyArn;
    /** 将结果限制为特定类型的实体（User, Group） */
    public String entityFilter;
    public String marker;
    public Integer maxItems = 100;
    
    @Override
    public void validate() {
        ValidationUtils.validatePolicyArn(policyArn, errorMessages);
        
        if (entityFilter != null && !PolicyEntity.TYPE_USER.equals(entityFilter) && !PolicyEntity.TYPE_GROUP.equals(entityFilter)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyEntityFilterInvalid", 
                    "Value '" + entityFilter + "' at 'entityFilter' failed to satisfy constraint: Member must satisfy enum value set: [User, Group]");
            errorMessages.add(errorMessage);
        }
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
        ValidationUtils.validateMarker(marker, errorMessages);
    }
    
    public String getRowPrefix(Policy policy) {
        String entityType = entityFilter == null ? "" : entityFilter;
        return "entity|" + getAccountId() + "|" + policy.scope  + "|" +  policy.policyName.toLowerCase() + "|" + entityType;
    }
    
    public String getResource() {
        return policyArn;
    }
    
    @Override
    public String getResourceArn() {
        return policyArn;
    }
}
