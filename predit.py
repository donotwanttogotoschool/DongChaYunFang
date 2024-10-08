import pandas as pd
import sqlite3
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties

# 设置中文字体，您可能需要调整字体路径
font = FontProperties(fname='SimHei.ttf')  # SimHei.ttf为黑体的字体文件，需确保该文件存在

# 连接到SQLite数据库并读取数据
DATABASE_PATH = 'vulnerability_data.db'
conn = sqlite3.connect(DATABASE_PATH)
query = "SELECT release_date, severity_level, COUNT(*) as count FROM vulnerabilities GROUP BY release_date, severity_level"
df = pd.read_sql_query(query, conn)
conn.close()

# 转换release_date为日期格式并按日期排序
df['release_date'] = pd.to_datetime(df['release_date'])
df = df.sort_values(by='release_date')

# 将数据按月汇总，并将不同的severity_level作为列
df_monthly = df.pivot_table(values='count', index=df['release_date'].dt.to_period('M'), columns='severity_level', aggfunc='sum', fill_value=0)
df_monthly.index = df_monthly.index.to_timestamp()

# 绘制堆叠面积图
plt.figure(figsize=(10, 6))
df_monthly.plot(kind='area', stacked=True, alpha=0.7, ax=plt.gca())
plt.title('2023年不同危险等级的每月漏洞数量', fontproperties=font)
plt.xlabel('日期', fontproperties=font)
plt.ylabel('漏洞数量', fontproperties=font)
plt.legend(title='危险等级', loc='upper left', prop=font)
plt.tight_layout()
plt.show()
