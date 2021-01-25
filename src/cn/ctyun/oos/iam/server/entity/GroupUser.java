package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;

/**
 * IAM组下用户
 * 用于维护组和用户的关系
 * @author wangduo
 *
 */
@HBaseTable(entityClass = Group.class)
public class GroupUser extends HBaseEntity {
    
    @Qualifier
    public String accountId;
    @Qualifier
    public String groupName;
    @Qualifier
    public String userName;
    @Qualifier
    public Long joinDate;
    
    /**
     * 获取用户
     * @return
     */
    public User getUser() {
        User user = new User();
        user.accountId = accountId;
        user.userName = userName;
        return user;
    }

    public String getGroupPrefix() {
        return "user|" + accountId + "|" + groupName.toLowerCase() + "|";
    }
    
    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes(getGroupPrefix() + userName.toLowerCase());
    }
    
}
