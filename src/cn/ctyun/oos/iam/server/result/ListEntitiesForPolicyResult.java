package cn.ctyun.oos.iam.server.result;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.server.entity.Group;
import cn.ctyun.oos.iam.server.entity.PolicyEntity;
import cn.ctyun.oos.iam.server.entity.User;

/**
 * 列出指定托管策略所附加的所有IAM用户和组返回结果
 * @author wangduo
 *
 */
public class ListEntitiesForPolicyResult extends Result {

    public List<User> policyUsers = new ArrayList<>();
    public List<Group> policyGroups = new ArrayList<>();
    public Boolean isTruncated;
    public String marker;
    public Long total;
    
    public ListEntitiesForPolicyResult(PageResult<PolicyEntity> pageResult) {
        for (PolicyEntity policyEntity : pageResult.list) {
            if (PolicyEntity.TYPE_USER.equals(policyEntity.entityType)) {
                User user = new User();
                user.userId = policyEntity.id;
                user.userName = policyEntity.entityName;
                policyUsers.add(user);
            } else if (PolicyEntity.TYPE_GROUP.equals(policyEntity.entityType)) {
                Group group = new Group();
                group.groupId = policyEntity.id;
                group.groupName = policyEntity.entityName;
                policyGroups.add(group);
            }
        }
        this.isTruncated = pageResult.isTruncated;
        this.marker = pageResult.marker;
        this.total = pageResult.total;
    }
}
