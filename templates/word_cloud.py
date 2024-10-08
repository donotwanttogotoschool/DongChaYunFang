import sqlite3
from wordcloud import WordCloud, STOPWORDS
import matplotlib.pyplot as plt
import os

# 确保数据库路径正确
db_path = r'E:\数媒\洞察云防：漏洞态势观测站\app\vulnerability_data.db'
print(f"Database path exists: {os.path.exists(db_path)}")

# 连接到 SQLite 数据库
try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 查询 vulnerability_type 字段的所有内容
    query = "SELECT vulnerability_type FROM vulnerabilities"
    cursor.execute(query)
    descriptions = cursor.fetchall()

    # 将描述合并为一个字符串
    text = ' '.join([desc[0] for desc in descriptions])

    # 定义停用词，添加自定义的词语
    custom_stopwords = set(STOPWORDS)
    custom_stopwords.add('其他')  # 添加要去掉的词语

    # 生成词云，指定支持中文的字体路径和停用词
    wordcloud = WordCloud(
        font_path='C:\\Windows\\Fonts\\simhei.ttf',  # 指定系统中的中文字体路径（Windows 中的黑体）
        width=800,
        height=400,
        background_color='white',
        max_words=200,
        contour_color='steelblue',
        contour_width=3,
        stopwords=custom_stopwords  # 使用自定义的停用词列表
    ).generate(text)

    # 显示词云
    plt.figure(figsize=(10, 5))
    plt.imshow(wordcloud, interpolation='bilinear')
    plt.axis('off')

    # 保存词云图
    save_path = 'static/wordcloud.png'
    plt.savefig(save_path)
    print(f"Wordcloud saved at: {save_path}")

    plt.show()

except sqlite3.OperationalError as e:
    print(f"Error connecting to database: {e}")

finally:
    # 关闭数据库连接
    if 'conn' in locals():
        conn.close()
