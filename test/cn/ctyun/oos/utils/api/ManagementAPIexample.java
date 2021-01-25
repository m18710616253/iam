package cn.ctyun.oos.utils.api;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hdfs.protocol.proto.HdfsProtos.SnapshottableDirectoryListingProto;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.oos.hbase.HBaseRole;
import cn.ctyun.oos.hbase.HBaseUserToRole;
import cn.ctyun.oos.hbase.MetaClient;
import cn.ctyun.oos.metadata.OwnerMeta;
import cn.ctyun.oos.metadata.RoleMeta;
import cn.ctyun.oos.metadata.UserToRoleMeta;
import cn.ctyun.oos.metadata.RoleMeta.RolePermission;
import common.time.TimeUtils;
import common.tuple.Pair;

public class ManagementAPIexample {
    
    String httpOrHttps="https";
    String host="oos-cd.ctyunapi.cn";
    int port=9462;
    String signVersion="V4";
    String regionName="cd";
    private static String ownerName = "test_user4_6463084869102845087@a.cn"; 
    public static String ak = "d5486d49a20339f164a5";
    public static String sk = "adf5f77f00e9dc5d39da406d00005e45e68b8b3d"; 
    
    
//    public static final String ak = "test_user4_6463084869102845087@a.cn44";
//    public static final String sk="secretKey44";
    
    public static OwnerMeta owner = new OwnerMeta(ownerName);
    public static MetaClient metaClient = MetaClient.getGlobalClient();
    
    static String today = TimeUtils.toYYYY_MM_dd(new Date());

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        addUsrToRole(Arrays.asList("yxregion1"));
    }

    @Before
    public void setUp() throws Exception {
    }
    
    @Test
    public void test() {
        HashMap<String, String> headers=new HashMap<String, String>();
        headers.put("Content-Type", "application/octet-stream;charset=utf-8");
        String bucketName="yx-bucket-1";
        Pair<Integer, String> getUsage=ManagementAPITestUtils.GetUsage(httpOrHttps, host, port, signVersion,regionName, ak, sk, today, today, null, "byDay", headers);
        assertEquals(200, getUsage.first().intValue());
        
        Pair<Integer, String> getAvailBW=ManagementAPITestUtils.GetAvailBW(httpOrHttps, host, port, signVersion, regionName,ak, sk, today+"-00-05", today+"-08-05", "yxregion1", null);
        assertEquals(200, getAvailBW.first().intValue());
        
        Pair<Integer, String> getBandwidth=ManagementAPITestUtils.GetBandwidth(httpOrHttps, host, port, signVersion, regionName,ak, sk, today+"-00-05", today+"-00-10", bucketName, null);
        assertEquals(200, getBandwidth.first().intValue());
        
        Pair<Integer, String> getConnection=ManagementAPITestUtils.GetConnection(httpOrHttps, host, port, signVersion, regionName,ak, sk, today+"-00-05", today+"-00-10", bucketName, null);
        assertEquals(200, getConnection.first().intValue());
        
        Pair<Integer, String> getCapacity=ManagementAPITestUtils.GetCapacity(httpOrHttps, host, port, signVersion, regionName,ak, sk, today, today, bucketName, "byHour", "yxregion1", null);
        assertEquals(200, getCapacity.first().intValue());
        
        Pair<Integer, String> getDeleteCapacity=ManagementAPITestUtils.GetDeleteCapacity(httpOrHttps, host, port, signVersion, regionName,ak, sk, today, today, bucketName, "byDay", "yxregion1", null);
        assertEquals(200, getDeleteCapacity.first().intValue());
        
        Pair<Integer, String> getTraffics=ManagementAPITestUtils.GetTraffics(httpOrHttps, host, port, signVersion, regionName,ak, sk,today, today, bucketName, "by5min", "yxregion1", "all", "internet", "direct", null);
        assertEquals(200, getTraffics.first().intValue());
        
        Pair<Integer, String> getAvailableBandwidth=ManagementAPITestUtils.GetAvailableBandwidth(httpOrHttps, host, port, signVersion, regionName,ak, sk,today, today, "by5min", "yxregion1", "inbound", "noninternet", null);
        assertEquals(200, getAvailableBandwidth.first().intValue());
        
        Pair<Integer, String> getRequests=ManagementAPITestUtils.GetRequests(httpOrHttps, host, port, signVersion, regionName,ak, sk,today, today, bucketName, "byDay", "yxregion1", "all", "put", null);
        assertEquals(200, getRequests.first().intValue());
        
        Pair<Integer, String> getReturnCode=ManagementAPITestUtils.GetReturnCode(httpOrHttps, host, port, signVersion, regionName,ak, sk,today, today, bucketName, "byDay", "yxregion1", "all", "get", "Response500", null);
        assertEquals(200, getReturnCode.first().intValue());
        
        Pair<Integer, String> getConcurrentConnection=ManagementAPITestUtils.GetConcurrentConnection(httpOrHttps, host, port, signVersion, regionName,ak, sk,today, today, bucketName, "by5min", "yxregion1", "all", null);
        assertEquals(200, getConcurrentConnection.first().intValue());
    }
    
    public static void addUsrToRole(List<String> scope) throws Exception {
        Configuration conf = GlobalHHZConfig.getConfig();
        Configuration globalConf = GlobalHHZConfig.getConfig();
        HBaseAdmin globalHbaseAdmin = new HBaseAdmin(globalConf);
        HBaseRole.dropTable(conf);
        HBaseRole.createTable(globalHbaseAdmin);
        HBaseUserToRole.dropTable(conf);
        HBaseUserToRole.createTable(globalHbaseAdmin);
        globalHbaseAdmin.close();

        Map<RolePermission, List<String>> pools = new TreeMap<>();
        pools.put(RoleMeta.RolePermission.PERMISSION_AVAIL_DATAREGION, scope);
        Map<RolePermission, List<String>> regions = new TreeMap<>();
        regions.put(RoleMeta.RolePermission.PERMISSION_AVAIL_BW, scope);
        RoleMeta role = new RoleMeta("user", "for common use", pools,regions);

        metaClient.roleInsert(role);
        //绑定role
        metaClient.ownerSelect(owner);
        List<Long> roleID = new ArrayList<Long>();
        roleID.add(role.getId());
        UserToRoleMeta userToRole = new UserToRoleMeta(owner.getId(), roleID);
        metaClient.userToRoleInsert(userToRole );
    }

}
