package cn.ctyun.oos.iam.server.result;

import cn.ctyun.oos.iam.server.util.DateFormat;
import cn.ctyun.oos.iam.server.util.TrailDate;

/**
 * AccessKey响应结果
 * @author wangduo
 *
 */
public class AccessKeyResult extends Result {
    public String userName;
    public String accessKeyId;
    public String status;
    public String isPrimary;
    public String secretAccessKey;
    @DateFormat
    @TrailDate
    public Long createDate;
    @DateFormat
    @TrailDate
    public Long lastUsedDate;
}
