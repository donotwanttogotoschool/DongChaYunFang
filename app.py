from flask import Flask, render_template, request, redirect, url_for, jsonify, session,send_file
from statsmodels.tsa.arima.model import ARIMA
import sqlite3
import pandas as pd
from wordcloud import WordCloud, STOPWORDS 
from datetime import datetime
import matplotlib.pyplot as plt
import os
import subprocess
import numpy as np

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'vulnerability_data.db')

@app.route('/vulnerability_stats')
def get_vulnerability_stats():
    try:
        query = """
        SELECT vulnerability_type, severity_level, COUNT(*) as count
        FROM vulnerabilities
        GROUP BY vulnerability_type, severity_level
        """
        df = get_m_data(query)
        
        vuln_counts = {}  # 用于表格统计的漏洞数据
        vuln_types = {}   # 用于柱状图的漏洞类型数据
        total_vulns = 0   # 总漏洞数

        # 遍历数据，统计总数、各类型数量及高危/超危漏洞数量
        for _, row in df.iterrows():
            vuln_type = row['vulnerability_type']
            severity = row['severity_level']
            count = row['count']
            
            # 统计总漏洞数
            total_vulns += count

            # 按类型统计漏洞数量
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + count

            # 统计高危和超危漏洞数量
            if severity in ['高危', '超危']:
                vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + count

        # 返回处理结果
        return jsonify({
            'total_vulns': total_vulns,
            'vuln_types': vuln_types,
            'vuln_counts': vuln_counts
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def get_m_data(query=None):
    conn = sqlite3.connect(DATABASE_PATH)
    if query:
        df = pd.read_sql_query(query, conn)
    else:
        df = pd.read_sql_query('SELECT * FROM vulnerabilities', conn)
    conn.close()
    return df

# 获取2023年的漏洞数据并做预测
def predict_top_vulnerabilities():
    # 查询2023年高危漏洞数据
    query = """
    SELECT vulnerability_type, COUNT(*) as count
    FROM vulnerabilities
    WHERE strftime('%Y', release_date) = '2023' AND severity_level = '高危'
    GROUP BY vulnerability_type
    """
    df = get_m_data(query)
    
    # 使用 ARIMA 模型预测2024年数据
    predictions = {}
    for vulnerability_type in df['vulnerability_type'].unique():
        # 创建时间序列模型
        count_data = df[df['vulnerability_type'] == vulnerability_type]['count']
        if len(count_data) >= 5:  # ARIMA 要求至少有足够的数据点
            model = ARIMA(count_data, order=(5, 1, 0))
            model_fit = model.fit()
            forecast = model_fit.forecast(steps=12)  # 预测接下来12个月
            predictions[vulnerability_type] = forecast.sum()  # 总数量预测
        else:
            predictions[vulnerability_type] = count_data.mean() * 12  # 用平均值估算

    # 将预测值按照数量排序，返回Top 5
    sorted_predictions = sorted(predictions.items(), key=lambda x: x[1], reverse=True)[:5]

    # 返回预测结果
    return sorted_predictions
# 定义API接口，返回预测的Top 5漏洞
@app.route('/get_top_vulnerabilities_2024')
def get_top_vulnerabilities_2024():
    try:
        predicted_vulnerabilities = predict_top_vulnerabilities()
        result = [{'vulnerability_type': v[0], 'predicted_count': v[1]} for v in predicted_vulnerabilities]
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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


    
#if __name__ == '__main__':
#    app.run(debug=True)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
