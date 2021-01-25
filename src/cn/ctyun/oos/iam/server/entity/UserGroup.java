package cn.ctyun.oos.iam.server.entity;

import org.apache.hadoop.hbase.util.Bytes;

import cn.ctyun.oos.iam.server.hbase.HBaseEntity;
import cn.ctyun.oos.iam.server.hbase.HBaseTable;
import cn.ctyun.oos.iam.server.hbase.Qualifier;

/**
 * IAM用户的组
 * 用于维护用户和组的关系
 * @author wangduo
 *
 */
@HBaseTable(entityClass = User.class)
public class UserGroup extends HBaseEntity {
    
    @Qualifier
    public String accountId;
    @Qualifier
    public String userName;
    @Qualifier
    public String groupName;
    
    /**
     * 获取用户和组关系的前缀
     * 用于查询用户下的组关系
     * @return
     */
    public String getUserPrefix() {
        return "group|" + accountId + "|" + userName.toLowerCase() + "|";
    }
    
    @Override
    public byte[] getRowKey() {
        return Bytes.toBytes(getUserPrefix() +  groupName.toLowerCase());
    }
    
    /**
     * 获取组的rowKey
     * @return
     */
    public Group getGroup() {
        Group group = new Group();
        group.accountId = accountId;
        group.groupName = groupName;
        return group;
    }


}
