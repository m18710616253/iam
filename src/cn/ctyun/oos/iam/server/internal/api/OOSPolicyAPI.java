package cn.ctyun.oos.iam.server.internal.api;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.filter.CompareFilter.CompareOp;
import org.apache.hadoop.hbase.filter.Filter;
import org.apache.hadoop.hbase.filter.SingleColumnValueFilter;
import org.apache.hadoop.hbase.filter.SubstringComparator;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.accesscontroller.util.IAMException;
import cn.ctyun.oos.iam.server.entity.Policy;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.PolicyScopeType;
import cn.ctyun.oos.iam.server.result.PageResult;
import cn.ctyun.oos.metadata.IamChangeEvent;
import cn.ctyun.oos.metadata.IamChangeEvent.ChangeType;

/**
 * 系统策略接口
 * @author wangduo
 *
 */
public class OOSPolicyAPI {

    private static final Log log = LogFactory.getLog(OOSPolicyAPI.class);
    
    private static MetaClient client = MetaClient.getGlobalClient();
    
    /**
     * 创建策略
     * @param param
     * @return
     * @throws Exception 
     */
    public static Policy createPolicy(OOSPolicyParam param) throws Exception {
        
        // 系统策略参数校验
        checkPolicyParam(param);
        Policy policy = param.getCreatePolicy();
        // 策略已存在
        if (HBaseUtils.exist(policy)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("oosPolicyAlreadyExists", "OOS policy with name %s already exists.", param.policyName);
            throw new IAMException(409, "EntityAlreadyExists", errorMessage);
        }
        HBaseUtils.put(policy);
        return HBaseUtils.get(policy);
    }
    
    /**
     * 系统策略参数校验
     * @param param
     * @throws IAMException
     */
    private static void checkPolicyParam(OOSPolicyParam param) throws IAMException {
        if (StringUtils.isEmpty(param.policyName)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyNameEmpty", "PolicyName must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        if (StringUtils.isEmpty(param.policyDocument)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyDocumentEmpty", "PolicyDocument must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        if (StringUtils.isEmpty(param.description)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyDescriptionEmpty", "Description must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        // 解析policy，保证访问控制时可以正常解析
        try {
            AccessPolicy.fromJson(param.policyDocument);
        } catch (PolicyParseException e) {
            log.error("Parse policy json failed. policyDocument:" + param.policyDocument, e);
            throw new IAMException(400, "MalformedPolicyDocument", new IAMErrorMessage(e.messageCode, e.getMessage(), e.params));
        }
    }
    
    /**
     * 更新策略
     * @param param
     * @return
     * @throws IAMException 
     * @throws IOException 
     */
    public static Policy updatePolicy(OOSPolicyParam param) throws IAMException, IOException {

        // 系统策略参数校验
        checkPolicyParam(param);
        Policy policy = param.getUpdatePolicy();
        // 策略不存在
        if (!HBaseUtils.exist(policy)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("oosPolicyNotExists", "The OOS policy with name %s cannot be found.", param.policyName);
            throw new IAMException(404, "NoSuchEntity", errorMessage);
        }
        HBaseUtils.put(policy);
        client.iamChangeEventInsert(new IamChangeEvent(ChangeType.POLICY, policy.accountId, policy.policyName));
        return HBaseUtils.get(policy);
    }
    
    /**
     * 删除指定的IAM策略
     * 在删除托管策略之前，必须先将策略与其附加到的所有用户，组分离
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static void deletePolicy(OOSPolicyParam param) throws BaseException, IOException {
        
        Policy policy = param.getQueryPolicy();
        if (StringUtils.isEmpty(param.policyName)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyNameEmpty", "PolicyName must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        policy = HBaseUtils.get(policy);
        // 策略不存在
        if (policy == null) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("oosPolicyNotExists", "The OOS policy with name %s cannot be found.", param.policyName);
            throw new IAMException(404, "NoSuchEntity", errorMessage);
        }
        // 如果已经有附加，不允许删除系统策略
        if (policy.attachedTotal != null && policy.attachedTotal > 0) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("oosPolicyIsAttached", "The OOS policy with name %s is attached.", param.policyName);
            throw new IAMException(409, "DeleteConflict", errorMessage);
        }
        

        // 删除策略
        HBaseUtils.delete(policy);
    }

    /**
     * 获取指定的IAM策略
     * @param param
     * @throws BaseException 
     * @throws IOException 
     */
    public static Policy getPolicy(OOSPolicyParam param) throws BaseException, IOException {

        Policy policy = param.getQueryPolicy();
        if (StringUtils.isEmpty(param.policyName)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("policyNameEmpty", "PolicyName must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        // 策略不存在
        if (!HBaseUtils.exist(policy)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("oosPolicyNotExists", "The OOS policy with name %s cannot be found.", param.policyName);
            throw new IAMException(404, "NoSuchEntity", errorMessage);
        }
        return HBaseUtils.get(policy);
    }
    
    
    /**
     * 分页获取系统策略列表
     * @param param
     * @throws Throwable 
     */
    public static PageResult<Policy> listPolicies(ListOOSPoliciesParam param) throws Throwable {

        Scan scan = new Scan();
        // 策略名称模糊匹配
        if (param.policyName != null) {
            Filter filter = new SingleColumnValueFilter(Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(Policy.QUALIFIER_POLICY_NAME), 
                    CompareOp.EQUAL, new SubstringComparator(param.policyName));
            scan.setFilter(filter);
        }
        String oosPrefix = PolicyScopeType.OOS.name() + "|";
        scan.setStartRow(Bytes.toBytes(oosPrefix));
        scan.setStopRow(Bytes.toBytes(oosPrefix + Character.MAX_VALUE));
        // marker设置
        if (param.marker != null && param.marker.compareTo(oosPrefix) > 0) {
            scan.setStartRow(Bytes.toBytes(param.marker + Character.MIN_VALUE));
        }
        PageResult<Policy> pageResult = HBaseUtils.scan(scan, param.maxItems, Policy.class, true);
        return pageResult;
    }
}
