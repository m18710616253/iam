package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.param.UserType;

/**
 * 用户与MFA设备关系
 * 用于维护用户和MFA设备的关系
 * 每个用户只有一个MFA设备
 * @author wangduo
 *
 */
@HBaseTable(entityClass = MFADevice.class)
public class UserMFADevice extends HBaseEntity {
    
    @Qualifier
    /** 用户类型 user root */
    public String userType;
    @Qualifier
    public String accountId;
    @Qualifier
    public String userName;
    /** 虚拟MFA设备的名称 */
    @Qualifier
    public String virtualMFADeviceName;
    
    @Override
    public byte[] getRowKey() {
        if (UserType.Root.value.equals(userType)) {
            return Bytes.toBytes(UserType.Root.value + "|" + accountId);
        } 
        return Bytes.toBytes(UserType.User.value + "|" + accountId + "|" + userName.toLowerCase());
    }

    public MFADevice getMFADevice() {
        MFADevice mFADevice = new MFADevice();
        mFADevice.accountId = accountId;
        mFADevice.virtualMFADeviceName = virtualMFADeviceName;
        return mFADevice;
    }
}
