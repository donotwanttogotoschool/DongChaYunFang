# 基础镜像，选择Python 3.12的官方镜像
FROM python:3.12-slim

# 设置工作目录
WORKDIR /app

# 复制requirements.txt文件到容器中
COPY requirements.txt /app/

# 安装依赖包
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码到工作目录
COPY . /app

# 暴露Flask应用的默认端口（如5000）
EXPOSE 5000

# 设置环境变量以便Flask读取端口
ENV PORT 5000

# 运行应用
CMD ["python", "app.py"]
