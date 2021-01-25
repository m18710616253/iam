package cn.ctyun.oos.iam.accesscontroller.policy.reader;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.amazonaws.util.json.JSONArray;
import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.PolicyParseException;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.ConditionFactory;


/**
 * JSON策略解析工具
 */
public class JsonPolicyReader {

    /**
     * 将json的策略转换为policy对象
     * @param jsonString
     * @return
     * @throws PolicyParseException
     */
    public AccessPolicy createPolicyFromJsonString(String jsonString) throws PolicyParseException  {

        if (jsonString == null) {
            throw new PolicyParseException("policyJSONNull", "Policy JSON string must not be null.");
        }

        AccessPolicy policy = new AccessPolicy();
        policy.jsonString = jsonString;
        List<Statement> statements = new LinkedList<Statement>();
        try {
            JSONObject jPolicy = new JSONObject(jsonString);
            
            // 获取version
            if (jPolicy.has(JsonDocumentFields.VERSION)) {
                policy.version = jPolicy.getString(JsonDocumentFields.VERSION);
                if (!AccessPolicy.DEFAULT_POLICY_VERSION.equals(policy.version)) {
                    throw new PolicyParseException("invalidPolicyVersion", "The policy must contain a valid version string.");
                }
            } else {
                throw new PolicyParseException("invalidPolicyVersion", "The policy must contain a valid version string.");
            }

            JSONArray jStatements = jPolicy.getJSONArray(JsonDocumentFields.STATEMENT);
            // statement id set，用于id判重
            Set<String> idSet = new HashSet<String>();
            for (int i = 0 ; i < jStatements.length() ; i++) {
                Statement statement = convertStatement(jStatements.getJSONObject(i));
                statements.add(statement);
                if (statement.id != null) {
                    // statement id不能重复
                    if (idSet.contains(statement.id)) {
                        throw new PolicyParseException("sameStatementId", "The Statement Ids in the policy are not unique.");
                    }
                    idSet.add(statement.id);
                }
            }
        } catch (JSONException e) {
            throw new PolicyParseException("syntaxErrorInPolicy", "Syntax errors in policy.", e);
        }
        policy.statements = statements;
        return policy;
    }

    /**
     * 将json转换为statement
     * 
     * @param jStatement
     * @return
     * @throws JSONException
     * @throws PolicyParseException 
     */
    private  Statement convertStatement(JSONObject jStatement) throws JSONException, PolicyParseException {
        if (!jStatement.has(JsonDocumentFields.STATEMENT_EFFECT)) {
            throw new PolicyParseException("missEffect", "Missing required field Effect.");
        }

        Statement statement;
        String jEffect = jStatement.getString(JsonDocumentFields.STATEMENT_EFFECT);
        if (JsonDocumentFields.EFFECT_VALUE_ALLOW.equals(jEffect)) {
            statement = new Statement(Effect.Allow);
        } else if (JsonDocumentFields.EFFECT_VALUE_DENY.equals(jEffect)) {
            statement = new Statement(Effect.Deny);
        } else {
            throw new PolicyParseException("invalidEffect", "Invalid effect: %s.", jEffect);
        }

        // 获取statement的id
        if (jStatement.has(JsonDocumentFields.STATEMENT_ID)) {
            statement.id = jStatement.getString(JsonDocumentFields.STATEMENT_ID);
        }
        
        convertActions(statement, jStatement);
        convertResources(statement, jStatement);
        convertCondition(statement, jStatement);
        convertPrincipals(statement, jStatement);
        
        return statement;
    }


    /**
     * Action元素转换
     * @param statement
     * @param jStatement
     * @throws JSONException
     * @throws PolicyParseException 
     */
    private void convertActions(Statement statement, JSONObject jStatement) throws JSONException, PolicyParseException {
        
        if (jStatement.has(JsonDocumentFields.NOT_ACTION) && jStatement.has(JsonDocumentFields.ACTION)) {
            throw new PolicyParseException("alreadyHasAction", "Statement/policy already has instance of Action.");
        }
        if (jStatement.has(JsonDocumentFields.ACTION)) {
            statement.ationEffect = JsonDocumentFields.ACTION;
        }
        if (jStatement.has(JsonDocumentFields.NOT_ACTION)) {
            statement.ationEffect = JsonDocumentFields.NOT_ACTION;
        }
        if (statement.ationEffect == null) {
            throw new PolicyParseException("missAction", "Missing required field Action.");
        }
        Object value = jStatement.opt(statement.ationEffect);
        if (value instanceof JSONArray) {
            JSONArray jValues = jStatement.getJSONArray(statement.ationEffect);
            for (int index = 0; index < jValues.length(); index++) {
                statement.actions.add(jValues.getString(index));
            }
        } else {
            if (!isEmpty(value)) {
                statement.actions.add(value.toString());
            }
        }
        if (statement.actions.size() == 0) {
            throw new PolicyParseException("policyActionEmpty", "Required field Action cannot be empty.");
        }
    }

    /**
     * Resource元素转换
     * @param statement
     * @param jStatement
     * @throws JSONException
     * @throws PolicyParseException 
     */
    private void convertResources(Statement statement, JSONObject jStatement) throws JSONException, PolicyParseException {
        if (jStatement.has(JsonDocumentFields.NOT_RESOURCE) && jStatement.has(JsonDocumentFields.RESOURCE)) {
            throw new PolicyParseException("alreadyHasResource", "Statement/policy already has instance of Resource.");
        }
        if (jStatement.has(JsonDocumentFields.RESOURCE)) {
            statement.resourceEffect = JsonDocumentFields.RESOURCE;
        }
        if (jStatement.has(JsonDocumentFields.NOT_RESOURCE)) {
            statement.resourceEffect = JsonDocumentFields.NOT_RESOURCE;
        }
        if (statement.resourceEffect == null) {
            throw new PolicyParseException("missResource", "Missing required field Resource.");
        }
        Object value = jStatement.opt(statement.resourceEffect);
        if (value instanceof JSONArray) {
            JSONArray jValues = jStatement.getJSONArray(statement.resourceEffect);
            for (int index = 0; index < jValues.length(); index++) {
                statement.resources.add(jValues.getString(index));
            }
        } else {
            if (!isEmpty(value)) {
                statement.resources.add(value.toString());
            }
        }
        if (statement.resources.size() == 0) {
            throw new PolicyParseException("policyResourceEmpty", "Required field Resource cannot be empty.");
        }
    }
    
    /**
     * 判断json取值是否为空
     * @param value
     * @return
     */
    private boolean isEmpty(Object value) {
        return value == null || value.toString().length() == 0 || JSONObject.NULL.equals(value);
    }
    
    /**
     * Principal元素转换
     * 先实现基于身份的策略，这部分暂时不考虑处理
     * @param statement
     * @param jStatement
     * @throws JSONException
     */
    private void convertPrincipals(Statement statement, JSONObject jStatement) throws JSONException {
        if (!jStatement.has(JsonDocumentFields.PRINCIPAL)) {
            return;
        }
    }

    /**
     * 条件元素转换
     * @param statement
     * @param jStatement
     * @throws JSONException
     * @throws PolicyParseException
     */
    private void convertCondition(Statement statement, JSONObject jStatement) throws JSONException, PolicyParseException {
        if (!jStatement.has(JsonDocumentFields.CONDITION)) {
            return;
        }
        JSONObject jConditions = jStatement.getJSONObject(JsonDocumentFields.CONDITION);
        String[] types = JSONObject.getNames(jConditions);
        for (String type : types) {
             JSONObject jCondition = jConditions.getJSONObject(type);
             convertConditionRecord(statement, type, jCondition);
        }
    }

    /**
     * 转换为一个条件运算符
     * @param conditions
     * @param type
     * @param jCondition
     * @throws JSONException
     * @throws PolicyParseException
     */
    private void convertConditionRecord(Statement statement, String type, JSONObject jCondition) throws JSONException, PolicyParseException {
        
        String[] keys = JSONObject.getNames(jCondition);
        for (String key : keys) {
            List<String> values = new LinkedList<String>();
            Object value = jCondition.opt(key);
            if (value instanceof JSONArray) {
                JSONArray jValues = jCondition.getJSONArray(key);
                for (int index = 0; index < jValues.length(); index++) {
                    values.add(jValues.getString(index));
                }
            } else {
                values.add(value.toString());
            }
            Condition condition = ConditionFactory.newCondition(type, key, values);
            // 设置statement是否包含MFA相关的条件键
            if (condition.hasMFAKey()) {
                statement.containsMFAKey = true;
            }
            statement.conditions.add(condition);
        }
    }

}
