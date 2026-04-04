# 使用官方 Python 3.12 精简版作为基础镜像
FROM python:3.12-slim

# 设置容器内的工作目录
WORKDIR /app

# 复制本地的 requirements.txt 到容器的工作目录
COPY requirements.txt .

# 安装 Python 依赖（--no-cache-dir 减小镜像体积）
RUN pip install --no-cache-dir -r requirements.txt

# 复制整个项目到容器内
COPY . .

# 定义容器启动时执行的命令（允许用户追加参数）
ENTRYPOINT ["python", "-m", "infospy.scanner"]