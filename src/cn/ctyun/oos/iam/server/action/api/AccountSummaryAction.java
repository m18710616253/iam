package cn.ctyun.oos.iam.server.action.api;

import cn.ctyun.oos.iam.server.action.Action;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.param.GetAccountSummaryParam;
import cn.ctyun.oos.iam.server.result.GetAccountSummaryResult;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;

/**
 * 账户IAM的实体使用和配额信息相关接口
 * @author wangduo
 *
 */
@Action
public class AccountSummaryAction {
    
    /**
     * 获取IAM的实体使用和配额信息
     * @param param
     * @return
     * @throws Exception 
     */
    public static GetAccountSummaryResult getAccountSummary(GetAccountSummaryParam param) throws Exception {
        AccountSummary accountSummary = AccountSummaryService.getAccountSummary(param.getAccountId());
        accountSummary.accountAccessKeysPresent = param.currentOwner.currentAKNum;
        if (!param.isFromConsole) {
            accountSummary.accessKeysPerAccountQuota = null;
        }
        // 不展示根用户AK数量的限制
        GetAccountSummaryResult result = new GetAccountSummaryResult(accountSummary);
        return result;
    }
    
}
