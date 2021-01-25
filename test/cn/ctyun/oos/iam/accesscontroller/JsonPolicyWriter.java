package cn.ctyun.oos.iam.accesscontroller;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;

import cn.ctyun.oos.iam.accesscontroller.policy.AccessPolicy;
import cn.ctyun.oos.iam.accesscontroller.policy.Principal;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement;
import cn.ctyun.oos.iam.accesscontroller.policy.Statement.Effect;
import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;
import cn.ctyun.oos.iam.accesscontroller.policy.reader.JsonDocumentFields;

/**
 * 将AccessPolicy转换为JSON格式
 * 每次使用都要new一个新的
 */
public class JsonPolicyWriter {

    private JsonGenerator generator = null;

    private Writer writer;

    public JsonPolicyWriter() {
        writer = new StringWriter();
        try {
            generator = new JsonFactory().createGenerator(writer);;
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    public String writePolicyToString(AccessPolicy policy) {

        if(!isNotNull(policy))
            throw new IllegalArgumentException("Policy cannot be null");

        try {
            return jsonStringOf(policy);
        } catch (Exception e) {
            String message = "Unable to serialize policy to JSON string: "
                    + e.getMessage();
            throw new IllegalArgumentException(message, e);
        } finally {
            try { writer.close(); } catch (Exception e) { }
        }
    }

    /**
     * Converts the given <code>Policy</code> into a JSON String.
     *
     * @param policy
     *            the policy to be converted.
     * @return a JSON String of the specified policy object.
     */
    private String jsonStringOf(AccessPolicy policy) throws JsonGenerationException,
            IOException {
        generator.writeStartObject();

        writeJsonKeyValue(JsonDocumentFields.VERSION, policy.version);

        if (isNotNull(policy.id))
            writeJsonKeyValue(JsonDocumentFields.POLICY_ID, policy.id);

        writeJsonArrayStart(JsonDocumentFields.STATEMENT);

        for (Statement statement : policy.statements) {
            generator.writeStartObject();

            if (isNotNull(statement.id)) {
                writeJsonKeyValue(JsonDocumentFields.STATEMENT_ID, statement.id);
            }
            writeJsonKeyValue(JsonDocumentFields.STATEMENT_EFFECT, statement.effect.toString());

            List<Principal> principals = statement.principals;
            if (isNotNull(principals) && !principals.isEmpty())
                writePrincipals(principals,statement.principalEffect);

            List<String> actions = statement.actions;
            if (isNotNull(actions) && !actions.isEmpty())
                writeActions(actions, statement.ationEffect);

            List<String> resources = statement.resources;
            if (isNotNull(resources) && !resources.isEmpty())
                writeResources(resources, statement.resourceEffect);

            List<Condition> conditions = statement.conditions;
            if (isNotNull(conditions) && !conditions.isEmpty())
                writeConditions(conditions);

            generator.writeEndObject();
        }

        writeJsonArrayEnd();

        generator.writeEndObject();

        generator.flush();

        return writer.toString();

    }

    /**
     * Writes the list of conditions to the JSONGenerator.
     *
     * @param conditions
     *            the conditions to be written.
     */
    private void writeConditions(List<Condition> conditions)
            throws JsonGenerationException, IOException {
        Map<String, ConditionsByKey> conditionsByType = groupConditionsByTypeAndKey(conditions);

        writeJsonObjectStart(JsonDocumentFields.CONDITION);

        ConditionsByKey conditionsByKey;
        for (Map.Entry<String, ConditionsByKey> entry : conditionsByType
                .entrySet()) {
            conditionsByKey = conditionsByType.get(entry.getKey());

            writeJsonObjectStart(entry.getKey());
            for (String key : conditionsByKey.keySet()) {
                writeJsonArray(key, conditionsByKey.getConditionsByKey(key));
            }
            writeJsonObjectEnd();
        }
        writeJsonObjectEnd();
    }

    /**
     * Writes the list of <code>Action</code>s to the JSONGenerator.
     *
     * @param actions
     *            the list of the actions to be written.
     */
    private void writeActions(List<String> actions, String actionEffect)
            throws JsonGenerationException, IOException {
        if (actionEffect == null) {
            writeJsonArray(JsonDocumentFields.ACTION, actions);
        } else {
            writeJsonArray(actionEffect, actions);
        }
    }

    private void writeResources(List<String> resources, String resourceEffect) throws JsonGenerationException, IOException {
        if (resourceEffect == null) {
            writeJsonArray(JsonDocumentFields.RESOURCE, resources);
        } else {
            writeJsonArray(resourceEffect, resources);
        }
    }
    
    /**
     * Writes the list of <code>Principal</code>s to the JSONGenerator.
     *
     * @param principals
     *            the list of principals to be written.
     */
    private void writePrincipals(List<Principal> principals,String principalEffect)
            throws JsonGenerationException, IOException {
        String principalWord="";
    	if (principalEffect == null) {
    	    principalWord=JsonDocumentFields.PRINCIPAL;
        } else {
            principalWord=principalEffect;
        }
    	if (principals.size() == 1 && principals.get(0).equals(Principal.All)) {
            writeJsonKeyValue(principalWord, Principal.All.getId());
        } else {
            writeJsonObjectStart(principalWord);

            Map<String, List<String>> principalsByScheme = groupPrincipalByScheme(principals);

            List<String> principalValues;
            for (Map.Entry<String, List<String>> entry : principalsByScheme.entrySet()) {
                principalValues = principalsByScheme.get(entry.getKey());

                if (principalValues.size() == 1) {
                    writeJsonKeyValue(entry.getKey(), principalValues.get(0));
                } else {
                    writeJsonArray(entry.getKey(), principalValues);
                }

            }
            writeJsonObjectEnd();
        }
    }


    /**
     * Inner class to hold condition values for each key under a condition type.
     */
    static class ConditionsByKey {
        private Map<String,List<String>> conditionsByKey;

        public ConditionsByKey(){
            conditionsByKey = new LinkedHashMap<String,List<String>>();
        }

        public Map<String,List<String>> getConditionsByKey() {
            return conditionsByKey;
        }

        public void setConditionsByKey(Map<String,List<String>> conditionsByKey) {
            this.conditionsByKey = conditionsByKey;
        }

        public boolean containsKey(String key){
            return conditionsByKey.containsKey(key);
        }

        public List<String> getConditionsByKey(String key){
            return conditionsByKey.get(key);
        }

        public Set<String> keySet(){
            return conditionsByKey.keySet();
        }

        public void addValuesToKey(String key, List<String> values) {

            List<String> conditionValues = getConditionsByKey(key);
            if (conditionValues == null)
                conditionsByKey.put(key, new ArrayList<String>(values));
            else
                conditionValues.addAll(values);
        }
    }
    
    /**
     * Groups the list of <code>Principal</code>s by the Scheme.
     *
     * @param principals
     *            the list of <code>Principal</code>s
     * @return a map grouped by scheme of the principal.
     */
    private Map<String, List<String>> groupPrincipalByScheme(
            List<Principal> principals) {
        Map<String, List<String>> principalsByScheme = new LinkedHashMap<String, List<String>>();

        String provider;
        List<String> principalValues;
        for (Principal principal : principals) {
            provider = principal.getProvider();
            if (!principalsByScheme.containsKey(provider)) {
                principalsByScheme.put(provider, new ArrayList<String>());
            }
            principalValues = principalsByScheme.get(provider);
            principalValues.add(principal.getId());
        }

        return principalsByScheme;
    }

    /**
     * Groups the list of <code>Condition</code>s by the condition type and
     * condition key.
     *
     * @param conditions
     *            the list of conditions to be grouped
     * @return a map of conditions grouped by type and then key.
     */
    private Map<String, ConditionsByKey> groupConditionsByTypeAndKey(
            List<Condition> conditions) {
        Map<String, ConditionsByKey> conditionsByType = new LinkedHashMap<String, ConditionsByKey>();

        String type;
        String key;
        ConditionsByKey conditionsByKey;
        for (Condition condition : conditions) {
            type = condition.type;
            key = condition.conditionKey;

            if (!(conditionsByType.containsKey(type))) {
                conditionsByType.put(type, new ConditionsByKey());
            }

            conditionsByKey = conditionsByType.get(type);
            conditionsByKey.addValuesToKey(key, condition.values);
        }
        return conditionsByType;
    }

    /**
     * Writes an array along with its values to the JSONGenerator.
     *
     * @param arrayName
     *            name of the JSON array.
     * @param values
     *            values of the JSON array.
     */
    private void writeJsonArray(String arrayName, List<String> values)
            throws JsonGenerationException, IOException {
    	if (values.size()>1) {
    		writeJsonArrayStart(arrayName);
            for (String value : values)
                generator.writeString(value);
            writeJsonArrayEnd();
		}else {
			writeJsonKeyValue(arrayName,values.get(0));
		}
        
    }

    /**
     * Writes the Start of Object String to the JSONGenerator along with Object
     * Name.
     *
     * @param fieldName
     *            name of the JSON Object.
     */
    private void writeJsonObjectStart(String fieldName)
            throws JsonGenerationException, IOException {
        generator.writeObjectFieldStart(fieldName);
    }

    /**
     * Writes the End of Object String to the JSONGenerator.
     */
    private void writeJsonObjectEnd() throws JsonGenerationException, IOException {
        generator.writeEndObject();
    }

    /**
     * Writes the Start of Array String to the JSONGenerator along with Array
     * Name.
     *
     * @param fieldName
     *            name of the JSON array
     */
    private void writeJsonArrayStart(String fieldName)
            throws JsonGenerationException, IOException {
        generator.writeArrayFieldStart(fieldName);
    }

    /**
     * Writes the End of Array String to the JSONGenerator.
     */
    private void writeJsonArrayEnd() throws JsonGenerationException, IOException {
        generator.writeEndArray();
    }

    /**
     * Writes the given field and the value to the JsonGenerator
     *
     * @param fieldName
     *            the JSON field name
     * @param value
     *            value for the field
     */
    private void writeJsonKeyValue(String fieldName, String value)
            throws JsonGenerationException, IOException {
        generator.writeStringField(fieldName, value);
    }

    /**
     * Checks if the given object is not null.
     *
     * @param object
     *            the object compared to null.
     * @return true if the object is not null else false
     */
    private boolean isNotNull(Object object) {
        return null != object;
    }
    
    public static void main(String[] args) {
        AccessPolicy accessPolicy = new AccessPolicy();
        
        Statement statement = new Statement(Effect.Deny);
        statement.actions.add("iam:CreateUser");
        statement.resources.add("*");
        accessPolicy.statements.add(statement);
        
        String json = new JsonPolicyWriter().writePolicyToString(accessPolicy);
        System.out.println(json);
    }
    
}
