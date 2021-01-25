package cn.ctyun.oos.iam.server.result;

import com.fasterxml.jackson.core.JsonProcessingException;

import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.util.JSONUtils;

/**
 * 创建策略响应
 * @author wangduo
 *
 */
public class CreatePolicyResult extends Result {

    public Policy policy = new Policy();

    public CreatePolicyResult(Policy policy) {
        this.policy.policyName = policy.policyName;
        this.policy.policyId = policy.policyId;
        this.policy.isAttachable = policy.isAttachable;
        this.policy.attachmentCount = policy.attachmentCount;
        this.policy.createDate = policy.createDate;
        this.policy.updateDate = policy.updateDate;
        this.policy.description = policy.description;
        this.policy.arn = policy.getArn();
    }
    
    @Override
    public String toJson() throws JsonProcessingException {
        return JSONUtils.toTrailJSON(this);
    }
}
