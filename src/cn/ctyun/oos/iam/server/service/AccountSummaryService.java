package cn.ctyun.oos.iam.server.service;

import java.io.IOException;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.util.ExceptionUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.metadata.OwnerMeta;


/**
 * 账户IAM的实体使用和配额信息通用功能 （写逻辑）
 * @author wangduo
 *
 */
public class AccountSummaryService {
	
	private static MetaClient client = MetaClient.getGlobalClient();

    /**
     * 获取账户IAM的实体使用和配额信息 
     * @param accountId
     * @return AccountSummary
     * @throws Exception 
     */
    public static AccountSummary getAccountSummary(String accountId) throws Exception {
    	// 检查是否存在id为accountId的账户
    	OwnerMeta owner = new OwnerMeta(IAMStringUtils.getOwnerId(accountId));
    	if(!client.ownerSelectById(owner)) {
    	    throw ExceptionUtils.newNoSuchAccountException(accountId);
    	}
        // 获取账户下使用和配额信息
        AccountSummary accountSummary = new AccountSummary();
        accountSummary.accountId = accountId;
        accountSummary = HBaseUtils.get(accountSummary);
        if (accountSummary == null) {
            accountSummary = new AccountSummary();
        }
        accountSummary.accountId = accountId;
        // 用默认信息填补缺失计数信息
        fillWithDefaultSummaryInformation(accountSummary);
        // 使用全局配额补充缺失的配额信息
        fillWithQuotaInformation(getSystemQuota(), accountSummary);
        // 根用户AK数量
        accountSummary.accountAccessKeysPresent = owner.currentAKNum;
        return accountSummary;
    }
    
    /**
     * 修改账户IAM的配额信息 
     * @param accountId
     * @return
     * @throws Exception 
     */
    public static void putAccountQuota(AccountSummary accountQuota) throws Exception {
    	// 检查是否存在id为accountQuota.accountId的账户
    	OwnerMeta owner = new OwnerMeta(IAMStringUtils.getOwnerId(accountQuota.accountId));
    	if(!client.ownerSelectById(owner)) {
    	    throw ExceptionUtils.newNoSuchAccountException(accountQuota.accountId);
    	}
    	// 将账户实体使用信息设置成null，不做更新
    	unmodifiedInformation(accountQuota);
    	HBaseUtils.put(accountQuota);
    }
    
    //用户账号注销时删除用户记录
    public static void deleteAccountQuota(AccountSummary accountQuota) throws Exception {
        // 检查是否存在id为accountQuota.accountId的账户
        OwnerMeta owner = new OwnerMeta(IAMStringUtils.getOwnerId(accountQuota.accountId));
        if(!client.ownerSelectById(owner)) {
            throw ExceptionUtils.newNoSuchAccountException(accountQuota.accountId);
        }
        HBaseUtils.delete(accountQuota);
    }
    
    /**
     * 增加账户下指定实体的数量
     * @param accountId
     * @param qualifier 指定字段名称
     * @param count 增加的数值，可以是负值
     * @return
     * @throws IOException
     */
    public static long increment(String accountId, String qualifier, long count) throws IOException {
        AccountSummary accountSummary = new AccountSummary();
        accountSummary.accountId = accountId;
        return HBaseUtils.incrementColumnValue(accountSummary, Bytes.toBytes(qualifier), count);
    }
    
    /**
     * 获取全局配额信息 
     * @param
     * @return AccountSummary
     * @throws IOException
     */
    public static AccountSummary getSystemQuota() throws IOException {
        // 系统限额
    	AccountSummary systemQuota = new AccountSummary();
        systemQuota.accountId = AccountSummary.getSystemRowKey();
        systemQuota = HBaseUtils.get(systemQuota);
        if (systemQuota != null) {
        	fillWithQuotaInformation(getDefaultAccountSummary(), systemQuota);
        } else {
        	// 不存在全局配额信息返回默认的配额信息
            systemQuota = getDefaultAccountSummary();
            systemQuota.accountId = AccountSummary.getSystemRowKey();
        }
        // 将账户实体使用信息设置成null，不返回
        unmodifiedInformation(systemQuota);
        return systemQuota;
    }
    
    /**
     * 修改全局配额信息 
     * @param
     * @return
     * @throws IOException
     */
    public static void putSystemQuota(AccountSummary systemSummary) throws IOException {
    	systemSummary.accountId = AccountSummary.getSystemRowKey();
    	// 将账户实体使用信息设置成null，不做更新
    	unmodifiedInformation(systemSummary);
        HBaseUtils.put(systemSummary);
    }
    
    /**
     * 获取默认的实体使用和配额信息
     * @return AccountSummary
     */
    private static AccountSummary getDefaultAccountSummary() {
        AccountSummary accountSummary = new AccountSummary();
        accountSummary.users = 0L;
        accountSummary.groups = 0L;
        accountSummary.policies = 0L;
        accountSummary.mFADevices = 0L;
        accountSummary.mFADevicesInUse = 0L;
        accountSummary.accountAccessKeysPresent = 0L;
        accountSummary.usersQuota = 500L;
        accountSummary.groupsQuota = 30L;
        accountSummary.policiesQuota = 150L;
        accountSummary.groupsPerUserQuota = 10L;
        accountSummary.attachedPoliciesPerUserQuota = 10L;
        accountSummary.attachedPoliciesPerGroupQuota = 10L;
        accountSummary.accessKeysPerUserQuota = 2L;
        accountSummary.accessKeysPerAccountQuota = 2L;
        return accountSummary;
    }
    
    /**
     * 用默认信息填补缺失的项
     * @param accountSummary 
     */
    private static void fillWithDefaultSummaryInformation(AccountSummary accountSummary) {
    	AccountSummary defaultAccountSummary = getDefaultAccountSummary();
        if(accountSummary.users == null) {
     	  accountSummary.users = defaultAccountSummary.users;
        }
        if(accountSummary.groups == null) {
     	  accountSummary.groups = defaultAccountSummary.groups;
       }
        if(accountSummary.policies == null) {
     	  accountSummary.policies = defaultAccountSummary.policies;
        }
        if(accountSummary.mFADevices == null) {
     	  accountSummary.mFADevices = defaultAccountSummary.mFADevices;
        }
        if(accountSummary.mFADevicesInUse == null) {
     	  accountSummary.mFADevicesInUse = defaultAccountSummary.mFADevicesInUse;
        }
        if(accountSummary.accountAccessKeysPresent == null) {
      	  accountSummary.accountAccessKeysPresent = defaultAccountSummary.accountAccessKeysPresent;
        }
    }
    
    /**
     * 用默认信息填补缺失的项
     * @param to 
     */
    private static void fillWithQuotaInformation(AccountSummary from, AccountSummary to) {
        if(to.usersQuota == null) {
     	  to.usersQuota = from.usersQuota;
        }
        if(to.groupsQuota == null) {
     	  to.groupsQuota = from.groupsQuota;
        }
        if(to.policiesQuota == null) {
     	  to.policiesQuota = from.policiesQuota;
        }
        if(to.groupsPerUserQuota == null) {
     	  to.groupsPerUserQuota = from.groupsPerUserQuota;
        }
        if(to.attachedPoliciesPerUserQuota == null) {
     	  to.attachedPoliciesPerUserQuota = from.attachedPoliciesPerUserQuota;
        }
        if(to.attachedPoliciesPerGroupQuota == null) {
     	  to.attachedPoliciesPerGroupQuota = from.attachedPoliciesPerGroupQuota;
        }
        if(to.accessKeysPerUserQuota == null) {
     	  to.accessKeysPerUserQuota = from.accessKeysPerUserQuota;
        }
        if(to.accessKeysPerAccountQuota == null) {
     	  to.accessKeysPerAccountQuota = from.accessKeysPerAccountQuota;
        }
    }

    /**
     * 将账户实体使用信息设置成null，不做更新
     * @param accountSummary
     */
    private static void unmodifiedInformation(AccountSummary accountSummary) {
    	accountSummary.users = null;
    	accountSummary.groups = null;
    	accountSummary.policies = null;
    	accountSummary.mFADevices = null;
    	accountSummary.mFADevicesInUse = null;
    	accountSummary.accountAccessKeysPresent = null;
    }
}
