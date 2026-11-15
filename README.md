# 授权网关的挑战式会话采集

当前读取授权设备的公开连接说明，受保护检测资料需要合法 Digest 会话。所有演练凭据仅在本地有效。

## 运行

使用 Node.js 22。依赖版本已锁定，运行、测试和演示不下载任何数据或软件。运行时只使用 Node.js 内置模块。

- `npm test`：执行本地来源交互及收件存储测试。
- `npm run build`：逐个检查模块语法。
- `npm run demo`：启动本地来源，连接授权网关并由多个作业共享会话并发领取，打印真实收件结果与运行阶段后退出。演示凭据可用 `GATEWAY_USERNAME`、`GATEWAY_PASSWORD` 注入，默认仅为本地演练账号。
- `npm start`：在 127.0.0.1:8080 启动本地来源，PORT 可调整。`GET /health` 返回服务与当前来源版本；原有 `/_health` 仍可使用。

容器方式：`docker build -t collection-digest .`，然后 `docker run --rm --network none collection-digest`。镜像构建属于环境准备，运行时不访问公网。

## 项目结构

`src/domain.mjs` 提供授权网关连接与业务读取入口；`src/digest.mjs` 维护可共享的 Digest 会话，凭据、挑战与计数各有作用域；`src/client.mjs` 负责有限大小领取、挑战刷新、断连重试与重定向隔离；`src/journal.mjs` 记录不携带认证材料的运行阶段；`src/archive.mjs` 保存内容及来源凭据。`provider/` 是独立的本地来源服务，`docs/source-contract.md` 说明它的资料和状态约定。演示使用临时目录，正式接入可向业务入口传入持久目录。

本地服务中的机构、记录和文件都是合成业务资料，不使用真实账号、个人信息或第三方站点数据。当前演示通常十秒内结束，全部本地测试应在六十秒内结束。
