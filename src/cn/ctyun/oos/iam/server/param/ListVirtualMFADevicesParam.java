package cn.ctyun.oos.iam.server.param;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.util.ValidationUtils;

/**
 * 按分配状态列出AWS账户中定义的虚拟MFA设备请求参数
 * @author wangduo
 *
 */
public class ListVirtualMFADevicesParam extends ActionParameter {

    /** 要列出的设备的状态 Assigned | Unassigned | Any */
    public String assignmentStatus;
    public String marker;
    public Integer maxItems = 100;

    @Override
    public void validate() {
        if (assignmentStatus != null && AssignmentStatusType.fromValue(assignmentStatus) == null) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("mfaAssignmentStatusInvalid", 
                    "Value '" + assignmentStatus + "' at 'assignmentStatus' failed to satisfy constraint: Member must satisfy enum value set: [Unassigned, Any, Assigned]");
            errorMessages.add(errorMessage);
        }
        ValidationUtils.validateMarker(marker, errorMessages);
        ValidationUtils.validateMaxItems(maxItems, errorMessages);
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateMFAArn(getAccountId(), "*");
    }

}
