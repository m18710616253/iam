package cn.ctyun.oos.iam.server.result;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import cn.ctyun.oos.iam.server.entity.MFADevice;

/**
 * 获取用户的MFA返回结果
 * @author wangduo
 *
 */
public class ListMFADevicesResult extends Result {

    public List<MFADevice> mFADevices = new ArrayList<>();
    public boolean isTruncated = false;
    
    public ListMFADevicesResult() {
    }
    
    public ListMFADevicesResult(MFADevice mFADevice) {
        MFADevice mFADeviceResult = new MFADevice();
        if (StringUtils.isNotEmpty(mFADevice.userName)) {
            mFADeviceResult.userName = mFADevice.userName;
        }
        mFADeviceResult.serialNumber = mFADevice.getArn();
        mFADeviceResult.enableDate = mFADevice.enableDate;
        mFADevices.add(mFADeviceResult);
    }
}
