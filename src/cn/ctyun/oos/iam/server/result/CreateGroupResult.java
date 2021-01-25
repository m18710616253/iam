package cn.ctyun.oos.iam.server.result;

import com.fasterxml.jackson.core.JsonProcessingException;

import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.util.JSONUtils;

/**
 * CreateGroup返回结果
 * @author wangduo
 *
 */
public class CreateGroupResult extends Result {

    public Group group = new Group();
    
    public CreateGroupResult(Group group) {
        this.group.groupName = group.groupName;
        this.group.groupId = group.groupId;
        this.group.createDate = group.createDate;
        this.group.arn = group.getArn();
    }
    
    @Override
    public String toJson() throws JsonProcessingException {
        return JSONUtils.toTrailJSON(this);
    }
}
