package cn.ctyun.oos.utils.api;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.HashMap;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import common.tuple.Pair;

public class CloudTrailAPIexample {
    static String endpointUrlStr="https://oos-cd-cloudtrail.ctyunapi.cn:9458/";
    static String regionName="cd";
//    static String accessKey="d5486d49a20339f164a5";
//    static String secretKey="adf5f77f00e9dc5d39da406d00005e45e68b8b3d";
    public static final String accessKey="userak1";
    public static final String secretKey="usersk1";
    static String bucketName="yx-bucket-1";
    static boolean isTarget=true;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void test() {
        HashMap<String, String> headers=new HashMap<String, String>();
        headers.put("Content-Type", "application/octet-stream;charset=utf-8");
        String trailName="trail202003102";
        Pair<Integer, String> createtrail=CloudTrailAPITestUtils.CreateTrail(endpointUrlStr, regionName, accessKey, secretKey, trailName, bucketName, isTarget, headers);
        assertEquals(200, createtrail.first().intValue());
        System.out.println(createtrail.second());
        
        Pair<Integer, String> describeTrails=CloudTrailAPITestUtils.DescribeTrails(endpointUrlStr, regionName, accessKey, secretKey, Arrays.asList(trailName), isTarget, null);
        assertEquals(200, describeTrails.first().intValue());
        System.out.println(describeTrails.second());
        
        Pair<Integer, String> updateTrail=CloudTrailAPITestUtils.UpdateTrail(endpointUrlStr, regionName, accessKey, secretKey, trailName, bucketName, null, isTarget, null);
        assertEquals(200, updateTrail.first().intValue());
        System.out.println(updateTrail.second());
        
        Pair<Integer, String> putEventSelectors=CloudTrailAPITestUtils.PutEventSelectors(endpointUrlStr, regionName, accessKey, secretKey, trailName, "All", isTarget, null);
        assertEquals(200, putEventSelectors.first().intValue());
        System.out.println(putEventSelectors.second());
        
        Pair<Integer, String> getEventSelectors=CloudTrailAPITestUtils.GetEventSelectors(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, getEventSelectors.first().intValue());
        System.out.println(getEventSelectors.second());

        Pair<Integer, String> startLogging=CloudTrailAPITestUtils.StartLogging(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, startLogging.first().intValue());
        System.out.println(startLogging.second());
        
        Pair<Integer, String> getTrailStatus=CloudTrailAPITestUtils.GetTrailStatus(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, getTrailStatus.first().intValue());
        System.out.println(getTrailStatus.second());
        
        Pair<Integer, String> stopLogging=CloudTrailAPITestUtils.StopLogging(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, stopLogging.first().intValue());
        System.out.println(stopLogging.second());
        
        Pair<Integer, String> lookupEvents=CloudTrailAPITestUtils.LookupEvents(endpointUrlStr, regionName, accessKey, secretKey,"EventSource","oos-cn-cloudtrail.ctyunapi.cn", isTarget, null);
        assertEquals(200, lookupEvents.first().intValue());
        System.out.println(lookupEvents.second());
        
        Pair<Integer, String> deleteTrail=CloudTrailAPITestUtils.DeleteTrail(endpointUrlStr, regionName, accessKey, secretKey, trailName, isTarget, null);
        assertEquals(200, deleteTrail.first().intValue());
        System.out.println(deleteTrail.second());
    }

}
