package cn.ctyun.oos.iam.accesscontroller.policy.reader;

/**
 * policy JSON 字段
 *
 */
public class JsonDocumentFields {
    
     public static final String VERSION = "Version";
     public static final String POLICY_ID = "Id";
     public static final String STATEMENT = "Statement";
     public static final String STATEMENT_EFFECT = "Effect";
     public static final String EFFECT_VALUE_ALLOW = "Allow";
     public static final String EFFECT_VALUE_DENY = "Deny";
     public static final String STATEMENT_ID = "Sid";
     
     public static final String PRINCIPAL = "Principal";
     public static final String NOT_PRINCIPAL = "NotPrincipal";
     
     public static final String ACTION = "Action";
     public static final String NOT_ACTION = "NotAction";
     
     public static final String RESOURCE = "Resource";
     public static final String NOT_RESOURCE = "NotResource";
     
     public static final String CONDITION = "Condition";
}
