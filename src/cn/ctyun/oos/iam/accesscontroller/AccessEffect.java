package cn.ctyun.oos.iam.accesscontroller;

/**
 * 标识请求失败允许、拒绝或隐式拒绝
 * @author wangduo
 *
 */
public enum AccessEffect {
    /** 允许 */
    Allow, 
    /** 拒绝 */
    Deny, 
    /** 隐式拒绝 */
    ImplicitDeny;
}
