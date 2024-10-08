import sqlite3
import sys
import io

# Set the standard output to UTF-8 to handle special characters
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Connect to the SQLite database
db_path = r"E:\数媒\洞察云防：漏洞态势观测站\app\vulnerability_data.db"
conn = sqlite3.connect(db_path)

# Set the text factory to handle UTF-8 encoded data
conn.text_factory = lambda x: x.decode('utf-8', 'ignore')

cursor = conn.cursor()

# Query to count vulnerabilities by severity levels
query = """
    SELECT severity_level, COUNT(*) as count
    FROM vulnerabilities
    WHERE severity_level IN ('高危', '超危', '中危', '低危')
    GROUP BY severity_level
"""

# Execute the query and fetch the data
cursor.execute(query)
results = cursor.fetchall()

# Initialize a dictionary to store counts with the correct severity labels
severity_counts = {'高危': 0, '超危': 0, '中危': 0, '低危': 0}

# Populate the dictionary with fetched data
for severity, count in results:
    severity_counts[severity] = count

# Print the counts to verify the output
print(severity_counts)

# Close the database connection
cursor.close()
conn.close()
