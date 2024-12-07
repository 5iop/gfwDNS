# 使用多阶段构建
FROM golang:1.21-alpine AS builder

# 安装构建依赖
RUN apk add --no-cache git gcc musl-dev

# 设置工作目录
WORKDIR /build

# 首先复制 go.mod 和 go.sum
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 然后复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -o gfwdns

# 使用轻量级基础镜像
FROM alpine:latest

# 安装必要的运行时依赖
RUN apk add --no-cache ca-certificates tzdata

# 创建非root用户
RUN adduser -D -u 1000 dnsuser

# 创建配置目录
RUN mkdir -p /etc/gfwdns && \
    chown -R dnsuser:dnsuser /etc/gfwdns

# 从构建阶段复制二进制文件
COPY --from=builder /build/gfwdns /usr/local/bin/

# 设置用户
USER dnsuser

# 声明配置文件挂载点
VOLUME ["/etc/gfwdns"]

# 暴露DNS端口
EXPOSE 53/udp

# 设置启动命令
ENTRYPOINT ["/usr/local/bin/gfwdns", "-config", "/etc/gfwdns/config.yaml"]