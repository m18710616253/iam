package cn.ctyun.oos.iam.server.internal.api;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.iam.accesscontroller.util.ExceptionUtils;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.accesscontroller.util.IAMException;
import cn.ctyun.oos.iam.accesscontroller.util.IAMStringUtils;
import cn.ctyun.oos.iam.server.entity.AccountPasswordPolicy;
import cn.ctyun.oos.iam.server.entity.AccountSummary;
import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.service.AccountPasswordPolicyService;
import cn.ctyun.oos.iam.server.service.AccountSummaryService;
import cn.ctyun.oos.iam.server.service.IAMPolicyService;
import cn.ctyun.oos.iam.server.service.MFAService;
import cn.ctyun.oos.iam.signer.Misc;
import cn.ctyun.oos.metadata.AkSkMeta;
import cn.ctyun.oos.metadata.OwnerMeta;

/**
 * IAM Server 内部接口  写接口
 * 供其他服务进行调用
 * 
 * @author wangduo
 *
 */
public class IAMInternalAPI {

    private static final Log log = LogFactory.getLog(IAMInternalAPI.class);
    
    private static MetaClient client = MetaClient.getGlobalClient();
    
    /** 策略获取 */
    private static IAMPolicyService policyService = new IAMPolicyService();
    
    /**
     * 子用户登录接口
     * proxy调用
     * /internal/login
     * @param request
     * @param response
     * @throws Exception 
     */
    public static LoginResult login(LoginParam loginParam) throws Exception {

        // 创建登录结果
        LoginResult loginResult = new LoginResult();
        // 参数空校验
        if (StringUtils.isEmpty(loginParam.accountId)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accountIdEmpty", "AccountId must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        if (StringUtils.isEmpty(loginParam.userName)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("userNameEmpty", "UserName must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        if (StringUtils.isEmpty(loginParam.passwordMd5)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("passwordEmpty", "Password must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        //验证accountId的合法性
        Long id;
        try {
            id = IAMStringUtils.getOwnerId(loginParam.accountId);
        } catch (NumberFormatException e) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accountIdInvalid", "The specified value for accountId is invalid.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        //验证是否存在accountId账户
        OwnerMeta owner = new OwnerMeta(id);
        if(!client.ownerSelectById(owner)) {
            throw ExceptionUtils.newNoSuchAccountException(loginParam.accountId);
        }
        
        // 获取登录用户信息
        User loginUser = HBaseUtils.get(loginParam.getUser());
        // 验证用户是否存在
        if (loginUser == null) {
            throw ExceptionUtils.newNoSuchUserException(loginParam.userName);
        }
        // 验证是否有登录权限
        if (StringUtils.isEmpty(loginUser.password)) {
            throw ExceptionUtils.newNoSuchLoginProfileException(loginParam.userName);
        }
        // 计算密码的MD5
        String passwordMd5 = Misc.getMd5(IAMStringUtils.passwordDecode(loginUser.password));
        if (!passwordMd5.equals(loginParam.passwordMd5)) {
            log.error("Login user " + loginUser.userName + " password was incorrect.");
            IAMErrorMessage errorMessage = new IAMErrorMessage("passwordIncorrect", "The password was incorrect.");
            throw new IAMException(403, "AccessDenied", errorMessage);
        }
        // 验证密码是否需要重置
        if (loginUser.passwordResetRequired != null && loginUser.passwordResetRequired) {
            loginResult.passwordResetRequired = true;
        }
        // 获取账户密码策略
        AccountPasswordPolicy passwordPolicy = AccountPasswordPolicyService.getAccountPasswordPolicy(loginParam.accountId);
        // 设置密码是否过期
        loginResult.passwordExpired = loginUser.passwordExpired(passwordPolicy.maxPasswordAge);
        loginResult.hardExpiry = passwordPolicy.hardExpiry;
        if (loginUser.passwordResetRequired != null && loginUser.passwordResetRequired) {
            loginResult.passwordResetRequired = true;
        }
        // 如果用户密码过期，判断是否需要管理员重置密码
        if (loginResult.passwordExpired) {
            if (passwordPolicy != null && passwordPolicy.hardExpiry != null && passwordPolicy.hardExpiry) {
                IAMErrorMessage errorMessage = new IAMErrorMessage("passwordExpired", 
                        "The password has expired, user cannot be accessed until an administrator resets the password.");
                throw new IAMException(403, "AccessDenied", errorMessage);
            }
        }
        // 获取用户MFA设备
        MFADevice mFADevice = MFAService.getUserMFADevice(loginParam.accountId, loginParam.userName);
        // 如果用户开启了MFA
        if (mFADevice != null) {
            if (loginParam.mFACode == null) {
                // 设置返回结果需要MFA验证码
                loginResult.mFACodeRequired = true;
                return loginResult;
            }
            // 校验MFA code  
            boolean mfaCorrect = MFAService.checkCode(mFADevice, loginParam.mFACode);
            if (mfaCorrect) {
                loginResult.multiFactorAuthPresent = true;
            } else {
                IAMErrorMessage errorMessage = new IAMErrorMessage("mfaCodeIncorrect", "The MFA code was incorrect.");
                throw new IAMException(403, "AccessDenied", errorMessage);
            }
        }
        // 获取用户的请求的accessKey
        AkSkMeta aksk = new AkSkMeta();
        aksk.accessKey = loginUser.builtInAccessKey;
        client.akskSelect(aksk);
        loginResult.accessKeyId = aksk.accessKey;
        loginResult.secretAccessKey = aksk.getSecretKey();
        loginResult.accountId = loginParam.accountId;
        
        // 更新最后登录时间及ip
        User user = loginParam.getUser();
        // 返回上次登录信息
        loginResult.iPLastUsed = loginUser.iPLastUsed;
        loginResult.passwordLastUsed = loginUser.passwordLastUsed;
        // 设置本次登录信息
        user.iPLastUsed = loginParam.loginIp;
        user.passwordLastUsed = System.currentTimeMillis();
        HBaseUtils.put(user);
        
        return loginResult;
    }
    
    /**
     * 获取用户的策略
     * @param accountUser
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    public static List<String> getUserPolices(User user) throws IOException {
        return policyService.getUserPoliciesByLoader(user.getUserKey());
    }
    
    /**
     * 批量获取用户的策略
     * @param userKeys 
     *          用户的key列表
     *          当其中userKey没有“|”作为分隔符时，其值是账户ID，
     *          先获取账户下的所有用户，在获取用户的策略
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    public static Map<String, List<String>> getUsersPolicyDocuments(List<String> userKeys) throws IOException {
        // 实际的userKey列表
        List<String> actualUserKeys = new ArrayList<>();
        // 获取userKeys中的accountId
        for (String userKey : userKeys) {
            if (StringUtils.isBlank(userKey)) {
                continue;
            }
            String[] accountIdAndUserName = userKey.split("\\|");
            if (accountIdAndUserName.length > 1) {
                actualUserKeys.add(userKey);
            } else {
                // userKey是账户ID的处理，获取账户下所有的userKey
                List<String> accountUserKeys = listAccountUserKeys(userKey);
                actualUserKeys.addAll(accountUserKeys);
            }
        }
        return policyService.getUsersPolicyDocuments(actualUserKeys);
    }
    
    /**
     * 获取账户下的userKey列表
     * @param accountId
     * @return
     * @throws IOException 
     */
    private static List<String> listAccountUserKeys(String accountId) throws IOException {
        
        Scan scan = new Scan();
        scan.setStartRow(Bytes.toBytes(accountId + Character.MIN_VALUE));
        scan.setStopRow(Bytes.toBytes(accountId + Character.MAX_VALUE));
        // 只查userName列
        byte [] family = Bytes.toBytes(Qualifier.DEFAULT_FAMILY);
        byte [] qualifier = Bytes.toBytes(User.QUALIFIER_USER_NAME);
        scan.addColumn(family, qualifier);
        List<User> users = HBaseUtils.listResult(scan, User.class);
        List<String> userKeys = new ArrayList<>();
        for (User user : users) {
            user.accountId = accountId;
            userKeys.add(user.getUserKey());
        }
        return userKeys;
    }
    
    
    /**
     * 获取账户的配额信息
     * @param accountId
     * @return
     * @throws Exception 
     */
    public static AccountSummary getAccountSummary(String accountId) throws Exception {
    	checkAccountId(accountId);
        return AccountSummaryService.getAccountSummary(accountId);
    }
    
    
    /**
     * 修改账户的配额信息
     * @param accountId
     * @return
     * @throws Exception 
     */
    public static void putAccountQuota(AccountSummary accountQuota) throws Exception {
    	checkAccountId(accountQuota.accountId);
    	AccountSummaryService.putAccountQuota(accountQuota);
    }
    
    
    /**
     * 获取全局的配额信息
     * @param 
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    public static AccountSummary getSystemQuota() throws IOException {
        AccountSummary systemQuota = AccountSummaryService.getSystemQuota();
    	return systemQuota;
    }
    
    
    /**
     * 修改全局配额信息
     * @param accountId
     * @return
     * @throws IOException 
     * @throws BaseException 
     */
    public static void putSystemQuota(AccountSummary systemQuota) throws IOException, BaseException {
    	AccountSummaryService.putSystemQuota(systemQuota);
    }
    
    
    /**
     * 验证MFA Code
     * @param loginParam
     * @return
     * @throws Exception 
     */
	public static CheckMFACodeResult checkMFACode(LoginParam loginParam) throws Exception {
		// 参数空校验
        if (StringUtils.isEmpty(loginParam.accountId)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accountIdEmpty", "AccountId must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        if (StringUtils.isEmpty(loginParam.userName)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("userNameEmpty", "UserName must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        if (loginParam.mFACode == null) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("mfaCodeEmpty", "MFACode must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        
        //验证accountId的合法性
        Long id;
        try {
			id = IAMStringUtils.getOwnerId(loginParam.accountId);
		} catch (NumberFormatException e) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accountIdInvalid", "The specified value for accountId is invalid.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
		}
        //验证是否存在accountId账户
        OwnerMeta owner = new OwnerMeta(id);
    	if(!client.ownerSelectById(owner)) {
    	    throw ExceptionUtils.newNoSuchAccountException(loginParam.accountId);
    	}
    	// 验证用户是否存在
    	User user = HBaseUtils.get(loginParam.getUser());
    	if (user == null) {
    	    throw ExceptionUtils.newNoSuchUserException(loginParam.userName);
    	}
        
		MFADevice mFADevice = MFAService.getUserMFADevice(loginParam.accountId, loginParam.userName);
		if (mFADevice == null) {
		    IAMErrorMessage errorMessage = new IAMErrorMessage("hasNoMFADevice", "The MFA must not be empty.");
			throw new IAMException(403, "NoSuchMFADevice", errorMessage);
		}
		boolean mfaCorrect = MFAService.checkCode(mFADevice, loginParam.mFACode);
		CheckMFACodeResult checkResult = new CheckMFACodeResult();
	    checkResult.multiFactorAuthPresent = mfaCorrect;
		return checkResult;
	}
	
	
	/**
     * 验证accountId，包括是否为空和是否是从ownerId转换而来的值
     * @param accountId
     * @return
     * @throws BaseException
     */
	private static void checkAccountId(String accountId) throws BaseException {
        if (StringUtils.isEmpty(accountId)) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accountIdEmpty", "AccountId must not be empty.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
        }
        try {
			IAMStringUtils.getOwnerId(accountId);
		} catch (NumberFormatException e) {
            IAMErrorMessage errorMessage = new IAMErrorMessage("accountIdInvalid", "The specified value for accountId is invalid.");
            throw new IAMException(400, "InvalidArgument", errorMessage);
		}
    }
}
