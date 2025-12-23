from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import subprocess
import zipfile
import shutil
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import secrets
import requests
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['BASE_UPLOAD_FOLDER'] = 'user_uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_ADMIN_ID = os.environ.get('TELEGRAM_ADMIN_ID', '')

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT,
                  status TEXT DEFAULT 'pending',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  approved_at TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def send_telegram_message(text):
    """Gửi thông báo đến admin qua Telegram"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_ADMIN_ID:
        return False
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        'chat_id': TELEGRAM_ADMIN_ID,
        'text': text,
        'parse_mode': 'HTML'
    }
    try:
        response = requests.post(url, data=data, timeout=10)
        return response.status_code == 200
    except:
        return False

def send_approval_request(username, email, user_id):
    """Gửi yêu cầu phê duyệt tài khoản đến admin"""
    message = f"""
🔔 <b>YÊU CẦU ĐĂNG KÝ TÀI KHOẢN MỚI</b>

👤 Username: <code>{username}</code>
📧 Email: {email or 'Không cung cấp'}
🆔 User ID: {user_id}
⏰ Thời gian: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

Để phê duyệt tài khoản này, vui lòng truy cập:
{request.host_url}admin/approve/{user_id}

Hoặc từ chối:
{request.host_url}admin/reject/{user_id}
"""
    return send_telegram_message(message)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # Kiểm tra trạng thái tài khoản
        conn = get_db()
        user = conn.execute('SELECT status FROM users WHERE id = ?', 
                           (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or user['status'] != 'approved':
            session.clear()
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def get_user_upload_folder(user_id):
    """Tạo và trả về thư mục upload riêng cho user"""
    folder = os.path.join(app.config['BASE_UPLOAD_FOLDER'], str(user_id))
    os.makedirs(folder, exist_ok=True)
    return folder

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'py', 'zip'}

def get_python_files(directory):
    """Lấy danh sách file Python trong thư mục"""
    python_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                rel_path = os.path.relpath(os.path.join(root, file), directory)
                python_files.append(rel_path)
    return sorted(python_files)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    
    if not username or not password:
        return jsonify({'error': 'Username và password không được để trống'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Password phải có ít nhất 6 ký tự'}), 400
    
    try:
        conn = get_db()
        
        # Kiểm tra username đã tồn tại
        existing = conn.execute('SELECT id FROM users WHERE username = ?', 
                               (username,)).fetchone()
        if existing:
            conn.close()
            return jsonify({'error': 'Username đã tồn tại'}), 400
        
        # Tạo tài khoản mới với trạng thái pending
        hashed_password = generate_password_hash(password)
        cursor = conn.execute(
            'INSERT INTO users (username, password, email, status) VALUES (?, ?, ?, ?)',
            (username, hashed_password, email, 'pending')
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Tạo thư mục riêng cho user
        get_user_upload_folder(user_id)
        
        # Gửi thông báo đến admin qua Telegram
        send_approval_request(username, email, user_id)
        
        return jsonify({
            'message': 'Đăng ký thành công! Tài khoản của bạn đang chờ admin phê duyệt.',
            'status': 'pending'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Vui lòng nhập username và password'}), 400
    
    try:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', 
                           (username,)).fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Username hoặc password không đúng'}), 401
        
        if not check_password_hash(user['password'], password):
            return jsonify({'error': 'Username hoặc password không đúng'}), 401
        
        if user['status'] == 'pending':
            return jsonify({
                'error': 'Tài khoản của bạn đang chờ admin phê duyệt',
                'status': 'pending'
            }), 403
        
        if user['status'] == 'rejected':
            return jsonify({
                'error': 'Tài khoản của bạn đã bị từ chối',
                'status': 'rejected'
            }), 403
        
        # Đăng nhập thành công
        session['user_id'] = user['id']
        session['username'] = user['username']
        
        return jsonify({
            'message': 'Đăng nhập thành công',
            'redirect': url_for('index')
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/approve/<int:user_id>')
def approve_user(user_id):
    """Phê duyệt tài khoản (chỉ admin)"""
    try:
        conn = get_db()
        user = conn.execute('SELECT username FROM users WHERE id = ?', 
                           (user_id,)).fetchone()
        
        if not user:
            conn.close()
            return "Không tìm thấy user", 404
        
        conn.execute(
            'UPDATE users SET status = ?, approved_at = CURRENT_TIMESTAMP WHERE id = ?',
            ('approved', user_id)
        )
        conn.commit()
        conn.close()
        
        # Gửi thông báo thành công
        send_telegram_message(f"✅ Đã phê duyệt tài khoản: <code>{user['username']}</code>")
        
        return f"Đã phê duyệt tài khoản {user['username']} thành công!"
        
    except Exception as e:
        return f"Lỗi: {str(e)}", 500

@app.route('/admin/reject/<int:user_id>')
def reject_user(user_id):
    """Từ chối tài khoản (chỉ admin)"""
    try:
        conn = get_db()
        user = conn.execute('SELECT username FROM users WHERE id = ?', 
                           (user_id,)).fetchone()
        
        if not user:
            conn.close()
            return "Không tìm thấy user", 404
        
        conn.execute('UPDATE users SET status = ? WHERE id = ?', 
                    ('rejected', user_id))
        conn.commit()
        conn.close()
        
        # Xóa thư mục của user
        user_folder = get_user_upload_folder(user_id)
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)
        
        # Gửi thông báo
        send_telegram_message(f"❌ Đã từ chối tài khoản: <code>{user['username']}</code>")
        
        return f"Đã từ chối tài khoản {user['username']}!"
        
    except Exception as e:
        return f"Lỗi: {str(e)}", 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Không có file nào được tải lên'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Chưa chọn file'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Chỉ chấp nhận file .py hoặc .zip'}), 400
        
        # Lấy thư mục riêng của user
        user_folder = get_user_upload_folder(session['user_id'])
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(user_folder, filename)
        file.save(filepath)
        
        # Nếu là file zip, giải nén
        if filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(filepath, 'r') as zip_ref:
                    zip_ref.extractall(user_folder)
                os.remove(filepath)
                message = f'Đã giải nén file {filename} thành công'
            except zipfile.BadZipFile:
                return jsonify({'error': 'File zip không hợp lệ'}), 400
        else:
            message = f'Đã tải lên file {filename} thành công'
        
        python_files = get_python_files(user_folder)
        
        return jsonify({
            'message': message,
            'python_files': python_files
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/get_files', methods=['GET'])
@login_required
def get_files():
    try:
        user_folder = get_user_upload_folder(session['user_id'])
        python_files = get_python_files(user_folder)
        return jsonify({'python_files': python_files}), 200
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/run', methods=['POST'])
@login_required
def run_file():
    try:
        data = request.get_json()
        selected_file = data.get('file')
        
        if not selected_file:
            return jsonify({'error': 'Chưa chọn file để chạy'}), 400
        
        if not selected_file.endswith('.py'):
            return jsonify({'error': 'File được chọn không phải là file Python (.py)'}), 400
        
        user_folder = get_user_upload_folder(session['user_id'])
        filepath = os.path.join(user_folder, selected_file)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File không tồn tại'}), 404
        
        result = subprocess.run(
            ['python3.12', filepath],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=user_folder
        )
        
        output = {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return jsonify(output), 200
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Timeout: File chạy quá 30 giây'}), 408
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/install_package', methods=['POST'])
@login_required
def install_package():
    try:
        data = request.get_json()
        package_name = data.get('package')
        
        if not package_name:
            return jsonify({'error': 'Chưa nhập tên package'}), 400
        
        result = subprocess.run(
            ['pip', 'install', package_name],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        output = {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'message': f'Đã cài đặt {package_name}' if result.returncode == 0 else 'Cài đặt thất bại'
        }
        
        return jsonify(output), 200
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Timeout: Cài đặt quá 2 phút'}), 408
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/list_packages', methods=['GET'])
@login_required
def list_packages():
    try:
        result = subprocess.run(
            ['pip', 'list'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return jsonify({'packages': result.stdout}), 200
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/clear', methods=['POST'])
@login_required
def clear_files():
    try:
        user_folder = get_user_upload_folder(session['user_id'])
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)
        os.makedirs(user_folder, exist_ok=True)
        return jsonify({'message': 'Đã xóa tất cả file của bạn'}), 200
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
