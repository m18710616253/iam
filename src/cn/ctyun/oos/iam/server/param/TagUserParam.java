package cn.ctyun.oos.iam.server.param;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.util.ARNUtils;
import cn.ctyun.oos.iam.accesscontroller.util.ResourcesUtils;
import cn.ctyun.oos.iam.server.action.ActionParameter;
import cn.ctyun.oos.iam.server.entity.Tag;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.Tags;
import cn.ctyun.oos.iam.server.util.ValidationUtils;
import cn.ctyun.oos.metadata.CloudTrailEvent.Resources;

/**
 * 用户标签请求参数
 * @author wangduo
 *
 */
public class TagUserParam extends ActionParameter {

    public String userName;
    public List<Tag> tags;
    
    /**
     * 请求参数解析
     * 用户标签需要单独处理
     * @throws BaseException 
     */
    @Override
    public void parseParams() throws BaseException {
       tags = Tags.parse(requestParams, errorMessages);
     }
    
    /**
     * 参数校验
     */
    @Override
    public void validate() {
        // 校验用户名
       ValidationUtils.validateUserName(userName, errorMessages);
    }

    /**
     * 获取用户查询参数
     * @return
     */
    public User getUserParam() {
        User user = new User();
        user.accountId = getAccountId();
        user.userName = userName;
        user.tags = tags;
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
}
