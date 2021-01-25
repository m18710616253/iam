package cn.ctyun.oos.iam.server.hbase;

/**
 * HBase实体基类
 * @author wangduo
 *
 */
public abstract class HBaseEntity {

    public static final String QUALIFIER_DELETED = "deleted";
    
    @Qualifier(name = QUALIFIER_DELETED)
    public Boolean deleted;
    
    /**
     * 获取实体的rowKey
     * @return
     */
    public abstract byte[] getRowKey();
    
    /**
     * 解析rowKey
     * @param bytes
     */
    public void parseRowKey(byte[] bytes) {};
}
