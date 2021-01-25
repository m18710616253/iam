package cn.ctyun.oos.iam.server.result;

import java.util.List;

import cn.ctyun.oos.iam.server.entity.Tag;

public class ListUserTagsResult extends Result {

    public List<Tag> tags;
    public boolean isTruncated = false;
    public String marker;
    public Long total;
    
}
