from flask import Flask, render_template, request, redirect, url_for, jsonify, session,send_file
from statsmodels.tsa.arima.model import ARIMA
import sqlite3
import pandas as pd
from wordcloud import WordCloud, STOPWORDS 
from datetime import datetime
import matplotlib.pyplot as plt
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'vulnerability_data.db')

def get_m_data(query=None):
    conn = sqlite3.connect(DATABASE_PATH)
    if query:
        df = pd.read_sql_query(query, conn)
    else:
        df = pd.read_sql_query('SELECT * FROM vulnerabilities', conn)
    conn.close()
    return df

# 预测每个严重等级的漏洞数量
def predict_vulnerabilities_by_severity():
    query = """
    SELECT strftime('%Y-%m', release_date) AS month, severity_level, COUNT(*) AS count
    FROM vulnerabilities
    GROUP BY month, severity_level
    """
    df = get_m_data(query)
    df['month'] = pd.to_datetime(df['month'])
    df = df.pivot_table(values='count', index='month', columns='severity_level', fill_value=0)
    
    forecast_data = {}
    for severity in df.columns:
        model = ARIMA(df[severity], order=(5, 1, 0)).fit()
        forecast = model.forecast(steps=12)
        forecast_dates = pd.date_range(start=df.index[-1] + pd.offsets.MonthBegin(), periods=12, freq='M')
        forecast_data[severity] = [{'date': date.strftime('%Y-%m'), 'predicted_count': count} 
                                   for date, count in zip(forecast_dates, forecast)]
    
    return forecast_data

@app.route('/predict_vulnerabilities', methods=['GET'])
def predict_vulnerabilities_route():
    try:
        forecast_data = predict_vulnerabilities_by_severity()
        return jsonify({'forecast': forecast_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_data():
    conn = sqlite3.connect(DATABASE_PATH)
    df = pd.read_sql_query('SELECT * FROM vulnerabilities', conn)
    conn.close()
    return df

@app.route('/monthly_data')
def monthly_data():
    try:
        # 获取每月漏洞总数
        query_monthly = """
        SELECT strftime('%Y-%m', release_date) AS month, COUNT(*) AS count
        FROM vulnerabilities
        GROUP BY month
        """
        monthly_counts = get_m_data(query_monthly).to_dict(orient='records')

        # 获取每天的漏洞数据
        query_daily = """
        SELECT release_date, COUNT(*) AS count
        FROM vulnerabilities
        GROUP BY release_date
        """
        daily_counts = get_m_data(query_daily).to_dict(orient='records')

        # 正确返回 JSON 格式
        return jsonify({'monthly_counts': monthly_counts, 'daily_counts': daily_counts})

    except Exception as e:
        # 输出错误信息并返回 500 错误
        print(f"Error fetching data: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # 简单的用户名密码验证
    if username == 'admin' and password == 'password':
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    else:
        return "登录失败，请重试！"

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/data')
def data():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    
    df = get_data()
    data = df.to_dict(orient='records')
    return jsonify(data)

@app.route('/word_cloud_map')
def word_cloud_map():
    return render_template('word_cloud_map.html')

@app.route('/predict')
def predict():
    return render_template('predict.html')

@app.route('/generate_wordcloud')
def generate_wordcloud():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    
    # 从数据库获取数据
    df = get_data()
    text = ' '.join(df['vulnerability_type'])

    # 定义停用词
    custom_stopwords = set(STOPWORDS)
    custom_stopwords.add('其他')


# 生成词云，设置透明背景并去掉边框
    wordcloud = WordCloud(
        font_path='C:\\Windows\\Fonts\\simhei.ttf',  # 指定中文字体路径
        width=800,
        height=400,
        mode='RGBA',  # 设置模式为 RGBA 支持透明
        background_color=None,  # 背景色设为 None 实现透明背景
        max_words=200,
        stopwords=custom_stopwords,
        colormap='winter',  # 使用亮色系的 colormap
        color_func=lambda *args, **kwargs: "white",  # 设置字体颜色为白色
        margin=0  # 去掉图像的边距
        ).generate(text)

    # 保存词云图
    save_path = 'static/wordcloud.png'
    wordcloud.to_file(save_path)
    
    return jsonify({"message": "Wordcloud generated successfully", "path": save_path})

@app.route('/vulnerability_intro')
def vulnerability_intro():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    
    return render_template('vulnerability_intro.html')


    
if __name__ == '__main__':
    app.run(debug=True)