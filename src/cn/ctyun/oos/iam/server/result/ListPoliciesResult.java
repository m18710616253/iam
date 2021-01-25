package cn.ctyun.oos.iam.server.result;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.server.entity.Policy;

/**
 * 策略列表结果
 * 
 * @author wangduo
 *
 */
public class ListPoliciesResult extends Result {

    public List<Policy> policies = new ArrayList<Policy>();
    public Boolean isTruncated;
    public String marker;
    public Long total;
    
    public ListPoliciesResult(PageResult<Policy> pageResult) {
        for (Policy policy : pageResult.list) {
            Policy policyResult = new Policy();
            policyResult.attachmentCount = policy.attachmentCount;
            policyResult.createDate = policy.createDate;
            policyResult.isAttachable = policy.isAttachable;
            policyResult.policyId = policy.policyId;
            policyResult.policyName = policy.policyName;
            policyResult.updateDate = policy.updateDate;
            policyResult.scope = policy.scope;
            policyResult.description = policy.description;
            policyResult.arn = policy.getArn();
            policies.add(policyResult);
        }
        this.isTruncated = pageResult.isTruncated;
        this.marker = pageResult.marker;
        this.total = pageResult.total;
    }
    
}
