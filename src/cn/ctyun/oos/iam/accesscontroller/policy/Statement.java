package cn.ctyun.oos.iam.accesscontroller.policy;

import java.util.ArrayList;
import java.util.List;

import cn.ctyun.oos.iam.accesscontroller.policy.condition.Condition;

/**
 * 策略Statement
 * @author wangduo
 *
 */
public class Statement {

    public static enum Effect {
        Allow, Deny;
    }

    public String id;
    public Effect effect;
    public List<Principal> principals = new ArrayList<>();
    public List<String> actions = new ArrayList<>();
    public List<String> resources = new ArrayList<>();
    public List<Condition> conditions = new ArrayList<>();

    /** action的作用 Action NotAction */
    public String ationEffect;
    /** principal的作用 Principal NotPrincipal */
    public String principalEffect;
    /** resource的作用 Resource NotResource */
    public String resourceEffect;

    /** 是否包含MFA相关的条件键 */
    public boolean containsMFAKey;
    
    public Statement(Effect effect) {
        this.effect = effect;
    }
}
