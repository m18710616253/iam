package cn.ctyun.oos.utils.env;

import cn.ctyun.oos.utils.HbaseUtils;

public class CleanTable {
    
    static String suffix="-yx";
    static String ostorId="xiao";
    
    public static void Clean_Owner() {
        HbaseUtils.TruncateTable("oos-owner"+suffix);
        HbaseUtils.TruncateTable("oos-aksk"+suffix); 
        HbaseUtils.TruncateTable("iam-user"+suffix); 
    }
    
    public static void Clean_OOS() { 
        HbaseUtils.TruncateTable("oos-bucket"+suffix);
        HbaseUtils.TruncateTable("oos-objects"+suffix);
        HbaseUtils.TruncateTable("oos-objectsMeta"+suffix);
        HbaseUtils.TruncateTable("oos-objectsMD5"+suffix);
        HbaseUtils.TruncateTable("oos-initialUpload"+suffix);
        HbaseUtils.TruncateTable("oos-initialUploadMeta"+suffix);
        HbaseUtils.TruncateTable("oos-initialUploadMD5"+suffix);
        HbaseUtils.TruncateTable("oos-upload"+suffix);
        HbaseUtils.TruncateTable("ostor-object-"+ostorId);
    }
    
    public static void Clean_IAM() {
        HbaseUtils.TruncateTable("iam-user"+suffix); 
        HbaseUtils.TruncateTable("iam-group"+suffix);
        HbaseUtils.TruncateTable("iam-policy"+suffix);
        HbaseUtils.TruncateTable("iam-mfaDevice"+suffix);
        HbaseUtils.TruncateTable("iam-accountSummary"+suffix);
    }
    
    public static void Clean_ManagementAPI() {
        HbaseUtils.TruncateTable("oos-minutesUsage"+suffix); 
    }
    
    public static void Clean_Cloudtrail() {
        HbaseUtils.TruncateTable("oos-cloudTrail"+suffix); 
        HbaseUtils.TruncateTable("oos-manageEvent"+suffix); 
    }
    
    
    
}
