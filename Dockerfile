# 使用多阶段构建
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装构建依赖
RUN apk add --no-cache git

# 拷贝源代码
COPY . .

# 构建应用
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -o gfwdns

# 使用轻量级基础镜像
FROM alpine:latest

# 安装必要的运行时依赖
RUN apk add --no-cache ca-certificates tzdata

# 创建非root用户
RUN adduser -D -u 1000 dnsuser

# 创建配置目录
RUN mkdir -p /etc/gfwdns && \
    chown -R dnsuser:dnsuser /etc/gfwdns

# 拷贝程序
COPY --from=builder /app/gfwdns /usr/local/bin/

# 设置用户
USER dnsuser

# 声明配置文件挂载点
VOLUME ["/etc/gfwdns"]

# 暴露DNS端口
EXPOSE 53/udp

# 设置启动命令
ENTRYPOINT ["/usr/local/bin/gfwdns", "-config", "/etc/gfwdns/config.yaml"]