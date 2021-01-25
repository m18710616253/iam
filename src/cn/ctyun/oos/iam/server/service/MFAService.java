package cn.ctyun.oos.iam.server.service;

import java.io.IOException;
import java.util.List;

import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.common.BaseException;
import cn.ctyun.oos.iam.accesscontroller.util.IAMErrorMessage;
import cn.ctyun.oos.iam.accesscontroller.util.IAMException;
import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.entity.UserMFADevice;
import cn.ctyun.oos.iam.server.hbase.HBaseUtils;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.UserType;
import cn.ctyun.oos.iam.server.util.MFAAuthenticator;

/**
 * 多因子认证通用逻辑
 * 
 * @author wangduo
 *
 */
public class MFAService {

	// mfaCode不能被重复使用的时间限制(5分半）
	private static final long mfaCheckTime = (MFAAuthenticator.WINDOW_SIZE * 2 + 1) * 30 * 1000;
	// 若5分钟内失败5次设备将被禁用
	private static final long failCheckTime = 5 * 60 * 1000;
	// 设备禁用时间，30分钟
	private static final long disableTime = 30 * 60 * 1000;

	/**
	 * 获取指定用户的MFA设备
	 * 
	 * @param accountId
	 * @param userName
	 * @return
	 * @throws IOException
	 */
	public static MFADevice getUserMFADevice(String accountId, String userName) throws IOException {
		UserMFADevice userMFADevice = new UserMFADevice();
		userMFADevice.accountId = accountId;
		userMFADevice.userName = userName;
		userMFADevice.userType = UserType.User.value;
		userMFADevice = HBaseUtils.get(userMFADevice);
		// 没有开启MFA
		if (userMFADevice == null) {
			return null;
		}
		return HBaseUtils.get(userMFADevice.getMFADevice());
	}

	/**
	 * 校验MFA code
	 * 
	 * @param mFADevice
	 * @param mFACode
	 * @return
	 * @throws IOException
	 * @throws BaseException
	 */
	public static boolean checkCode(MFADevice mFADevice, Long mFACode) throws IOException, BaseException {

		// 查看mfa设备是否被禁用
		long currentTime = System.currentTimeMillis();
		// 在禁用时间内不能进行验证码校验
		if (mFADevice.disableDate != null && mFADevice.disableDate >= currentTime) {
		    IAMErrorMessage errorMessage = new IAMErrorMessage("mfaDisabled", "The MFA is disabled.");
		    throw new IAMException(403, "AccessDenied", errorMessage);
		}
		// 判断校验码在5分半时间内是否被重复使用
		Get get = new Get(mFADevice.getRowKey());
		get.setTimeRange(currentTime - mfaCheckTime, currentTime);
		get.setMaxVersions();
		// 获取5分半内使用过的验证码
		List<Long> list = HBaseUtils.getVersions(mFADevice, Bytes.toBytes(Qualifier.DEFAULT_FAMILY),
				Bytes.toBytes(MFADevice.QUALIFIER_USED_CODE), get);
		// 判断是否重复使用
		if (list != null && !list.isEmpty()) {
			for (Long code : list) {
				// 有重复的
				if (code.equals(mFACode)) {
					saveFailInfo(mFADevice);
					IAMErrorMessage errorMessage = new IAMErrorMessage("mfaCodeUsed", "The MFA code is already used.");
					throw new IAMException(403, "AccessDenied", errorMessage);
				}
			}
		}

		// 校验MFA code
		boolean mfaCorrect = MFAAuthenticator.checkCode(mFADevice.base32StringSeed, mFACode);

		// 如果校验成功，将成功的mfaCode保存
		if (mfaCorrect) {
			MFADevice device = getMFADevice(mFADevice);
			device.usedCode = mFACode;
			HBaseUtils.put(device);
		}
		// 校验失败
		else {
			saveFailInfo(mFADevice);
		}

		return mfaCorrect;
	}

	/**
	 * 校验失败后将失败的校验保存起来，并判断是否需要禁用mfa设备
	 * @param mFADevice
	 * @throws IOException
	 */
	public static void saveFailInfo(MFADevice mFADevice) throws IOException, BaseException {
		MFADevice device = getMFADevice(mFADevice);
		List<Long> failList;
		Get get = new Get(mFADevice.getRowKey());
		get.setMaxVersions(4);
		// 若连续 checkAndPut 5次还未存入失败信息，表明在此过程中其他线程已存入5次失败信息，达到暴力破解的要求，此次请求失败
		for (int i = 0; i < 5; i++) {
			long currentTime = System.currentTimeMillis();
			device.failDate = currentTime;
			failList = HBaseUtils.getVersions(mFADevice, Bytes.toBytes(Qualifier.DEFAULT_FAMILY),
					Bytes.toBytes(MFADevice.QUALIFIER_FAIL_DATE), get);
			//获取最近4次的失败信息，若这4次失败信息中最老的失败信息在5分钟时间内，再加上这一次的失败信息，失败次数达到5次，禁用设备
			if (failList != null && failList.size() == 4 && failList.get(failList.size() - 1) > (currentTime - failCheckTime)) {
				// 禁用设备
				device.disableDate = currentTime + disableTime;
			}
			boolean success=HBaseUtils.checkAndPut(device, Bytes.toBytes(Qualifier.DEFAULT_FAMILY), Bytes.toBytes(MFADevice.QUALIFIER_FAIL_DATE),
					(failList == null || failList.size() == 0) ? null : Bytes.toBytes(failList.get(0)));
			if (success)
				return;
		}
		throw new BaseException(403, "AccessDenied", "The fail info can not be saved.");
	}

	public static MFADevice getMFADevice(MFADevice mfaDevice) {
		MFADevice device = new MFADevice();
		device.accountId = mfaDevice.accountId;
		device.virtualMFADeviceName = mfaDevice.virtualMFADeviceName;
		return device;
	}
}
