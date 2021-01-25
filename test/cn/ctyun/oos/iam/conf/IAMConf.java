package cn.ctyun.oos.iam.conf;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs.Ids;

import cn.ctyun.common.conf.GlobalHHZConfig;
import cn.ctyun.common.dsync.ZKClient;
import cn.ctyun.common.node.OosZKNode;

/**
 * 将IAM的配置文件保存到ZK上
 */
public class IAMConf {
    
    private void setZKData(String filePath, String zkPath) throws IOException, KeeperException, InterruptedException {
        File file = new File(filePath);
        byte[] data = Files.readAllBytes(file.toPath());
        ZKClient globalZKClient = new ZKClient(GlobalHHZConfig.getQuorumServers(), GlobalHHZConfig.getSessionTimeout());
        globalZKClient.createWithParents(zkPath, data, Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT);
        globalZKClient.setData(zkPath, data, -1);
        if (globalZKClient != null) {
            globalZKClient.close();
        }
    }
    
    public static void main(String[] args) throws Exception {
        IAMConf dc = new IAMConf();
        String rootPath ="E:\\workspace\\oos-deployment-6.5.0";
        String globalIamfilePath = rootPath + "\\conf\\global\\globalIamConfig.txt";
        String globalIamZkPath = OosZKNode.globalIamConfigPath;
        dc.setZKData(globalIamfilePath, globalIamZkPath);
        
        String iamfilePath = rootPath + "\\conf\\global\\iamServerConfig.txt";
        String iamZkPath = OosZKNode.iamServerConfigPath;
        dc.setZKData(iamfilePath, iamZkPath);
        System.out.println("set ZK Data success");
    }
    
}
