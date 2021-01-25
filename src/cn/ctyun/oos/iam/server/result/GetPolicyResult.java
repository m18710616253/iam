package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.entity.Policy;

/**
 * 获取指定的IAM策略返回结果
 * @author wangduo
 *
 */
public class GetPolicyResult extends Result {

    public Policy policy = new Policy();

    public GetPolicyResult(Policy policy) {
        this.policy.attachmentCount = policy.attachmentCount;
        this.policy.createDate = policy.createDate;
        this.policy.isAttachable = policy.isAttachable;
        this.policy.policyId = policy.policyId;
        this.policy.policyName = policy.policyName;
        this.policy.updateDate = policy.updateDate;
        this.policy.scope = policy.scope;
        this.policy.description = policy.description;
        // 对策略内容进行URLEncode
        this.policy.document = IAMStringUtils.urlEncode(policy.document);
        this.policy.arn = policy.getArn();
    }
}
