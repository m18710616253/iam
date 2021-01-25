package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;
import cn.ctyun.oos.iam.server.util.DateFormat;

/**
 * MFA设备
 * @author wangduo
 *
 */
@HBaseTable(name = "iam-mfaDevice", maxVersions = 100)
public class MFADevice extends HBaseEntity {

    public static final String QUALIFIER_STATUS = "status";
    public static final String QUALIFIER_USED_CODE = "usedCode";
    public static final String QUALIFIER_FAIL_DATE = "failDate";
    
    /** 账户ID */
    @Qualifier
    public String accountId;
    /** 虚拟设备名称 */
    @Qualifier
    public String virtualMFADeviceName;
    /** 用户类型 root, user */
    @Qualifier
    public String userType;
    /** 用户名称 */
    @Qualifier
    public String userName;
    /** 用户类型 Assigned, Unassigned */
    @Qualifier(name = QUALIFIER_STATUS)
    public String status;
    /** 对于虚拟MFA设备，序列号是设备ARN，ARN的最后一部分为VirtualMFADeviceName */
    @Qualifier
    public String serialNumber;
    /** 认证密钥（虚拟MFA使用） */
    @Qualifier
    public String base32StringSeed;
    /** 启用时间 */
    @Qualifier
    @DateFormat
    public Long enableDate;
    /** 创建时间 */
    @Qualifier
    @DateFormat
    public Long createDate;
    /** 使用过的验证码 */
    @Qualifier(name = QUALIFIER_USED_CODE)
    public Long usedCode;
    /** 失败时间，用于暴力破解 */
    @Qualifier(name = QUALIFIER_FAIL_DATE)
    @DateFormat 
    public Long failDate;
    /** 禁用截止时间，由于暴力破解导致设备禁用 */
    @Qualifier
    @DateFormat
    public Long disableDate;
    
    public String getArn() {
        return "arn:ctyun:iam::" + accountId + ":mfa/" + virtualMFADeviceName;
    }

    /**
     * 解析arn
     * @param arn
     * @throws ParseArnException
     */
    public void parseArn(String arn) throws ParseArnException {
        if (arn == null) {
            throw new ParseArnException();
        }
        // 不区分大小写，转小写
        arn = arn.toLowerCase();
        // 前缀不对
        if (!arn.startsWith("arn:ctyun:iam::") && !arn.startsWith("arn:aws:iam::")) {
            throw new ParseArnException();
        }
        String[] arnStrs = arn.split(":");
        if (arnStrs.length != 6) {
            throw new ParseArnException();
        }
        // 获取ARN账号部分
        accountId = arnStrs[4];
        String pathAndName = arnStrs[5];
        if (!pathAndName.startsWith("mfa/")) {
            throw new ParseArnException();
        }
        String[] strs = pathAndName.split("/");
        virtualMFADeviceName = strs[strs.length -1].toLowerCase();
    }   
    
    
    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes(accountId + "|" + virtualMFADeviceName.toLowerCase());
    }
    
    public User getUser() {
        User user = new User();
        user.accountId = accountId;
        user.userName = userName;
        return user;
    }
}
