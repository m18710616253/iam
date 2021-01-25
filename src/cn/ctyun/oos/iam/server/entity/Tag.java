package cn.ctyun.oos.iam.server.entity;

/**
 * 用户标签
 * @author wangduo
 *
 */
public class Tag implements Comparable<Tag> {

    public String key;
    public String value;
    
    @Override
    public int compareTo(Tag o) {
        return key.compareTo(o.key);
    }

    @Override
    public String toString() {
        return "Tag [key=" + key + ", value=" + value + "]";
    }
}
