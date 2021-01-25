package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.server.entity.User;
import cn.ctyun.oos.iam.server.util.DateFormat;

/**
 * 虚拟MFA设备创建信息
 * @author wangduo
 *
 */
public class VirtualMFADevice {

    public String serialNumber;
    public String base32StringSeed;
    public String qRCodePNG;
    
    @DateFormat
    public Long enableDate;
    public User user = new User();
   
    
}
