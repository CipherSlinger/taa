# 06-Nginx配置与启动

Nginx 不由 Docker Compose 管理，使用宿主机 Nginx。`nginx.conf` 和 `nginx-8.62.conf` 统一使用相同日志和 pid 文件名，只有 upstream IP 等机器差异单独配置。

## 配置文件

| 环境 | 配置文件 |
|---|---|
| A130 / 默认入口 | `/home/wuwm/prod-project/latti-client/nginx.conf` |
| 8.62 单机入口 | `/home/jiangsy/prod-project/latti-client/nginx-8.62.conf` |

先按所在机器设置变量：

```bash
# A130
NGINX_CONF=/home/wuwm/prod-project/latti-client/nginx.conf

# 8.62
NGINX_CONF=/home/jiangsy/prod-project/latti-client/nginx-8.62.conf
```

## 准备日志文件

统一日志文件：

```text
/tmp/latti-client-error.log
/tmp/latti-nginx-access.log
```

创建并赋权：

```bash
sudo touch /tmp/latti-client-error.log /tmp/latti-nginx-access.log
sudo chown root:adm /tmp/latti-client-error.log /tmp/latti-nginx-access.log
sudo chmod 664 /tmp/latti-client-error.log /tmp/latti-nginx-access.log
```

## 检查配置

```bash
sudo nginx -t -c "$NGINX_CONF"
```

## 首次启动

先确认 `8995` 未被项目 Nginx 占用：

```bash
sudo ss -lntp | grep ':8995'
```

启动：

```bash
sudo rm -f /tmp/latti-nginx.pid
sudo nginx -t -c "$NGINX_CONF"
sudo nginx -c "$NGINX_CONF"
```

`nginx -c` 是启动新实例；启动成功后不要重复执行。后续配置变更使用 reload。

## 重载配置

```bash
sudo nginx -t -c "$NGINX_CONF"
sudo nginx -s reload -c "$NGINX_CONF"
```

## 停止项目 Nginx

```bash
sudo nginx -s quit -c "$NGINX_CONF"
```

如果提示 pid 文件不存在、pid 为空，或 `8995` 端口占用，见 [13-故障排查](13-故障排查.md)。

## 验证

```bash
sudo ss -lntp | grep ':8995'
sudo cat /tmp/latti-nginx.pid
curl -i http://127.0.0.1:8995/api/v1/health
```

查看日志：

```bash
tail -f /tmp/latti-nginx-access.log
tail -f /tmp/latti-client-error.log
```

## 增加计算节点

在入口 Nginx 的 `upstream latti_nodes_by_user` 中加入：

```nginx
server <node-ip>:58996 max_fails=0;
```

然后执行：

```bash
sudo nginx -t -c "$NGINX_CONF"
sudo nginx -s reload -c "$NGINX_CONF"
```

## 路由要求

1. `/api/v1/health` 转发到 Node。
2. 普通业务接口按 `X-User-Id` 一致性哈希到 Node。
3. 缺少 `X-User-Id` 的业务请求返回 400。
