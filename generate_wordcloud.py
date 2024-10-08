import sqlite3
import pandas as pd
from wordcloud import WordCloud, STOPWORDS

# 数据库路径
DATABASE_PATH = 'vulnerability_data.db'


# 获取数据库中的数据
def get_vulnerability_names():
    conn = sqlite3.connect(DATABASE_PATH)
    df = pd.read_sql_query('SELECT DISTINCT vulnerability_name FROM vulnerabilities', conn)
    conn.close()
    return df['vulnerability_name'].tolist()


# 自定义颜色函数
def color_func(word, font_size, position, orientation, **kwargs):
    # 计算颜色深度
    intensity = int(255 * (font_size / 70))  # 假设最大字体大小为 70
    blue_intensity = 255  # 保持蓝色通道最大
    return f"rgb(0, {intensity}, {blue_intensity})"  # 保持颜色在蓝色系


# 生成词云
def generate_wordcloud():
    vulnerability_names = get_vulnerability_names()
    text = ' '.join(vulnerability_names)

    wordcloud = WordCloud(
        font_path='C:\\Windows\\Fonts\\simhei.ttf',  # 中文字体路径
        width=800,
        height=400,
        background_color=None,  # 透明背景
        mode='RGBA',
        max_words=200,
        stopwords=STOPWORDS,
        color_func=color_func,
        collocations=False,
        prefer_horizontal=1.0,
        max_font_size=70,  # 最大字体大小
        min_font_size=10,  # 最小字体大小
        scale=1.5  # 增大缩放比例
    ).generate(text)

    # 保存词云图
    save_path = 'static/wordcloud.png'
    wordcloud.to_file(save_path)

    print(f"Wordcloud generated successfully and saved to {save_path}")


# 调用函数生成词云
generate_wordcloud()
