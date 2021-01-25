package cn.ctyun.oos.iam.server.result;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.zxing.WriterException;

import cn.ctyun.oos.iam.server.entity.MFADevice;
import cn.ctyun.oos.iam.server.util.JSONUtils;
import cn.ctyun.oos.iam.server.util.MFAAuthenticator;

/**
 * 创建新的虚拟MFA设备返回结果
 * @author wangduo
 *
 */
public class CreateVirtualMFADeviceResult extends Result {

    public VirtualMFADevice virtualMFADevice = new VirtualMFADevice();
    
    public CreateVirtualMFADeviceResult() {}
    
    public CreateVirtualMFADeviceResult(String accountId, MFADevice mFADevice) throws WriterException, IOException {
        this.virtualMFADevice.serialNumber = mFADevice.serialNumber;
        this.virtualMFADevice.base32StringSeed = mFADevice.base32StringSeed;
        String qRCodePNG = MFAAuthenticator.generateQRCodePNG(mFADevice.virtualMFADeviceName, accountId, mFADevice.base32StringSeed);
        this.virtualMFADevice.qRCodePNG = qRCodePNG;
    }
    
    @Override
    public String toJson() throws JsonProcessingException {
        CreateVirtualMFADeviceResult trailResult = new CreateVirtualMFADeviceResult();
        trailResult.virtualMFADevice.serialNumber = virtualMFADevice.serialNumber;
        return JSONUtils.toTrailJSON(trailResult);
    }
}
