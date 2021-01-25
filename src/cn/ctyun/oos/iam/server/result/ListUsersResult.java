package cn.ctyun.oos.iam.server.result;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import cn.ctyun.oos.iam.server.entity.User;

/**
 * 用户列表结果
 * 
 * @author wangduo
 *
 */
public class ListUsersResult extends Result {

    public List<UserResult> users = new ArrayList<>();
    public boolean isTruncated = false;
    public String marker;
    public Long total;
    
    public ListUsersResult(PageResult<User> pageResult) {
        for (User user : pageResult.list) {
            UserResult userResult = new UserResult();
            userResult.userName = user.userName;
            userResult.userId = user.userId;
            userResult.arn = user.getArn();
            userResult.passwordCreateDate = user.passwordCreateDate;
            userResult.passwordLastUsed = user.passwordLastUsed;
            userResult.createDate = user.createDate;
            userResult.arn = user.getArn();
            if (StringUtils.isEmpty(user.mFAName)) {
                userResult.mFADeviceCount = 0;
            } else {
                userResult.mFADeviceCount = 1;
            }
            if (user.accessKeys == null || user.accessKeys.size() == 0) {
                userResult.accessKeyCount = 0;
            } else {
                userResult.accessKeyCount = user.accessKeys.size();
            }
            users.add(userResult);
        }
        this.isTruncated = pageResult.isTruncated;
        this.marker = pageResult.marker;
        this.total = pageResult.total;
    }
    
}
