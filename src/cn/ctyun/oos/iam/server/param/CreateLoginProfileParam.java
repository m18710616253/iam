package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;

import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 为指定用户创建密码
 * @author wangduo
 *
 */
public class CreateLoginProfileParam extends ActionParameter {

    public String password;
    public Boolean passwordResetRequired = false;
    public String userName;
    
    @Override
    public void validate() {
        ValidationUtils.validatePassword("password", password, errorMessages);
        ValidationUtils.validateUserName(userName, errorMessages);
    }

    public User getUser() {
        User user = new User();
        user.accountId = getAccountId();
        user.userName = userName;
        return user;
    }
    
    public String getResource() {
        return userName;
    }
    
    @Override
    public String getResourceArn() {
        return ARNUtils.generateUserArn(getAccountId(), userName);
    }
    
    /**
     * 返回日志审计记录的ARN
     * @return
     */
    @Override
    public List<Resources> getTrailResources() {
        List<Resources> resources = new ArrayList<>();
        resources.add(ResourcesUtils.generateUserResources(getAccountId(), userName));
        return resources;
    }
    
    @Override
    public String toJson() throws JsonProcessingException {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("passwordResetRequired", passwordResetRequired);
        map.put("userName", userName);
        return JSONUtils.toTrailJSON(map);
    }
}
