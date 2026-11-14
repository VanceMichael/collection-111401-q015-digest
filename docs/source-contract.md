# 授权检测网关

`/public-info` 公布设备和受保护目录地址。`/protected/catalog` 使用 RFC 7616 Digest，algorithm=SHA-256，qop=auth，opaque=local，realm=local-detector。本地账号为 operator，密码 local-demo-password；它们只是演练凭据，不含真实访问权限。业务中凭据由配置注入，不写进领域记录。

挑战的 nonce 由 generation 决定；改变 generation 后旧挑战返回 stale=true。同一 cnonce 的 nc 必须递增，十六进制八位计数；全新会话可以选择新 cnonce。服务支持合法并发认证，但不会放宽重放计数。请求 URI 包含查询部分，方法参与 HA2。仅支持此算法与 qop，其他组合应明确拒绝。

mode=redirect 让合法会话得到外来源重定向，不能自动把认证头转给新来源。来源审计只记录路径和体积，收件端也需要自行约束输出的敏感材料。

## 本地演练控制

`GET /_health` 返回服务健康状态；`GET /_audit` 仅返回请求路径、方法和体积，不记录凭据。`POST /_control` 接收 JSON，可调整 generation、mode、clock。控制端点只服务于本地演练，不是资料接口，也不是浏览器业务操作入口。每次重新启动服务都会恢复初始数据；生产接入时不部署此控制面。
