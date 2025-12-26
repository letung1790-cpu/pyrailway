from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort, send_file
import os
import sys
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
app.config['ADMIN_TOKEN'] = os.environ.get('ADMIN_TOKEN', secrets.token_urlsafe(32))

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = 'token'
TELEGRAM_ADMIN_ID = 5746258877

# Tự động tìm Python executable
PYTHON_EXECUTABLE = sys.executable

# ==================== DATABASE ====================

def init_db():
    """Khởi tạo database và tạo admin mặc định"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT,
                  status TEXT DEFAULT 'pending',
                  is_admin INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  approved_at TIMESTAMP)''')
    
    admin = c.execute('SELECT id FROM users WHERE is_admin = 1').fetchone()
    if not admin:
        admin_password = generate_password_hash('qh2729.!?@')
        c.execute('''INSERT INTO users (username, password, email, status, is_admin, approved_at)
                     VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                  ('admin', admin_password, 'admin@system.local', 'approved', 1))
    
    conn.commit()
    conn.close()

init_db()

def get_db():
    """Lấy kết nối database"""
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# ==================== TELEGRAM ====================

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

Để phê duyệt tài khoản này, vui lòng truy cập Admin Console
"""
    return send_telegram_message(message)

# ==================== DECORATORS ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db()
        u = conn.execute('SELECT status FROM users WHERE id = ?', 
                         (session['user_id'],)).fetchone()
        conn.close()
        
        if not u or u['status'] != 'approved':
            session.clear()
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator yêu cầu quyền admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin_login'))
        
        conn = get_db()
        u = conn.execute('SELECT is_admin, status FROM users WHERE id = ?', 
                         (session['user_id'],)).fetchone()
        conn.close()
        
        if not u or u['is_admin'] != 1 or u['status'] != 'approved':
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

def admin_token_required(f):
    """Decorator yêu cầu admin token cho private link"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.args.get('token')
        if token != app.config['ADMIN_TOKEN']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ==================== HELPERS ====================

def get_user_upload_folder(user_id):
    """Tạo và trả về thư mục upload riêng cho user"""
    folder = os.path.join(app.config['BASE_UPLOAD_FOLDER'], str(user_id))
    os.makedirs(folder, exist_ok=True)
    return folder

def allowed_file(filename):
    """Kiểm tra file có được phép upload không"""
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

def get_all_files(directory):
    """Lấy tất cả file trong thư mục"""
    all_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            rel_path = os.path.relpath(os.path.join(root, file), directory)
            full_path = os.path.join(root, file)
            file_size = os.path.getsize(full_path)
            all_files.append({
                'path': rel_path,
                'size': file_size,
                'modified': datetime.fromtimestamp(
                    os.path.getmtime(full_path)
                ).strftime('%Y-%m-%d %H:%M:%S')
            })
    return sorted(all_files, key=lambda x: x['path'])

# ==================== USER ROUTES ====================

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    u = conn.execute('SELECT is_admin FROM users WHERE id = ?', 
                     (session['user_id'],)).fetchone()
    conn.close()
    
    if u and u['is_admin'] == 1:
        return redirect(url_for('admin_dashboard'))
    
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
        existing = conn.execute('SELECT id FROM users WHERE username = ?', 
                                (username,)).fetchone()
        if existing:
            conn.close()
            return jsonify({'error': 'Username đã tồn tại'}), 400
        
        hashed_password = generate_password_hash(password)
        cursor = conn.execute(
            'INSERT INTO users (username, password, email, status) VALUES (?, ?, ?, ?)',
            (username, hashed_password, email, 'pending')
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        get_user_upload_folder(user_id)
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
        u = conn.execute('SELECT * FROM users WHERE username = ?', 
                         (username,)).fetchone()
        conn.close()
        
        if not u:
            return jsonify({'error': 'Username hoặc password không đúng'}), 401
        
        if not check_password_hash(u['password'], password):
            return jsonify({'error': 'Username hoặc password không đúng'}), 401
        
        if u['status'] == 'pending':
            return jsonify({
                'error': 'Tài khoản của bạn đang chờ admin phê duyệt',
                'status': 'pending'
            }), 403
        
        if u['status'] == 'rejected':
            return jsonify({
                'error': 'Tài khoản của bạn đã bị từ chối',
                'status': 'rejected'
            }), 403
        
        session['user_id'] = u['id']
        session['username'] = u['username']
        session['is_admin'] = u['is_admin']
        
        redirect_url = url_for('admin_dashboard') if u['is_admin'] else url_for('index')
        
        return jsonify({
            'message': 'Đăng nhập thành công',
            'redirect': redirect_url
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

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
        
        user_folder = get_user_upload_folder(session['user_id'])
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(user_folder, filename)
        file.save(filepath)
        
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

@app.route('/read_file', methods=['POST'])
@login_required
def read_file():
    """Đọc nội dung file để edit"""
    try:
        data = request.get_json()
        file_path = data.get('file')
        
        if not file_path:
            return jsonify({'error': 'Chưa chọn file'}), 400
        
        user_folder = get_user_upload_folder(session['user_id'])
        full_path = os.path.join(user_folder, file_path)
        
        if not os.path.exists(full_path):
            return jsonify({'error': 'File không tồn tại'}), 404
        
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return jsonify({
            'content': content,
            'filename': file_path
        }), 200
        
    except UnicodeDecodeError:
        return jsonify({'error': 'File không phải text file hoặc encoding không hợp lệ'}), 400
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/save_file', methods=['POST'])
@login_required
def save_file():
    """Lưu nội dung file sau khi edit"""
    try:
        data = request.get_json()
        file_path = data.get('file')
        content = data.get('content')
        
        if not file_path:
            return jsonify({'error': 'Chưa chọn file'}), 400
        
        if content is None:
            return jsonify({'error': 'Không có nội dung để lưu'}), 400
        
        user_folder = get_user_upload_folder(session['user_id'])
        full_path = os.path.join(user_folder, file_path)
        
        if not os.path.exists(full_path):
            return jsonify({'error': 'File không tồn tại'}), 404
        
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return jsonify({'message': f'Đã lưu file {file_path}'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/rename_file', methods=['POST'])
@login_required
def rename_file():
    """Đổi tên file"""
    try:
        data = request.get_json()
        old_path = data.get('old_name')
        new_name = data.get('new_name')
        
        if not old_path or not new_name:
            return jsonify({'error': 'Thiếu thông tin'}), 400
        
        new_name = secure_filename(new_name)
        
        user_folder = get_user_upload_folder(session['user_id'])
        old_full_path = os.path.join(user_folder, old_path)
        
        directory = os.path.dirname(old_full_path)
        new_full_path = os.path.join(directory, new_name)
        
        if not os.path.exists(old_full_path):
            return jsonify({'error': 'File không tồn tại'}), 404
        
        if os.path.exists(new_full_path):
            return jsonify({'error': 'Tên file mới đã tồn tại'}), 400
        
        os.rename(old_full_path, new_full_path)
        
        new_relative_path = os.path.relpath(new_full_path, user_folder)
        
        return jsonify({
            'message': f'Đã đổi tên thành {new_name}',
            'new_path': new_relative_path
        }), 200
        
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
        
        # FIX: Chỉ truyền relative path vì đã set cwd
        result = subprocess.run(
            [PYTHON_EXECUTABLE, selected_file],
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
            [PYTHON_EXECUTABLE, '-m', 'pip', 'install', package_name],
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
            [PYTHON_EXECUTABLE, '-m', 'pip', 'list'],
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

# ==================== ADMIN ROUTES ====================

@app.route('/admin/login', methods=['GET'])
def admin_login():
    return render_template('admin_login.html')

@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template(
        'admin_dashboard.html',
        username=session.get('username'),
        admin_token=app.config['ADMIN_TOKEN']
    )

@app.route('/admin/api/users', methods=['GET'])
@admin_required
def admin_get_users():
    """Lấy danh sách tất cả users"""
    try:
        conn = get_db()
        rows = conn.execute('''
            SELECT id, username, email, status, is_admin, 
                   created_at, approved_at 
            FROM users 
            ORDER BY created_at DESC
        ''').fetchall()
        conn.close()
        
        users_list = []
        for row in rows:
            user_folder = get_user_upload_folder(row['id'])
            file_count = len(get_python_files(user_folder))
            
            users_list.append({
                'id': row['id'],
                'username': row['username'],
                'email': row['email'],
                'status': row['status'],
                'is_admin': row['is_admin'],
                'created_at': row['created_at'],
                'approved_at': row['approved_at'],
                'file_count': file_count
            })
        
        return jsonify({'users': users_list}), 200
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/admin/api/user/<int:user_id>/files', methods=['GET'])
@admin_required
def admin_get_user_files(user_id):
    """Lấy danh sách file của một user"""
    try:
        user_folder = get_user_upload_folder(user_id)
        files = get_all_files(user_folder)
        return jsonify({'files': files}), 200
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/admin/api/user/<int:user_id>/download', methods=['GET'])
@admin_required
def admin_download_user_file(user_id):
    """Admin tải file của user"""
    try:
        file_path = request.args.get('path', '').strip()
        
        if not file_path:
            return jsonify({'error': 'Thiếu path file'}), 400
        
        user_folder = get_user_upload_folder(user_id)
        full_path = os.path.join(user_folder, file_path)
        
        if not os.path.exists(full_path) or not os.path.isfile(full_path):
            return jsonify({'error': 'File không tồn tại'}), 404
        
        # Bảo mật: kiểm tra path traversal
        real_path = os.path.realpath(full_path)
        real_folder = os.path.realpath(user_folder)
        
        if not real_path.startswith(real_folder):
            return jsonify({'error': 'Path không hợp lệ'}), 400
        
        return send_file(real_path, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/admin/api/user/<int:user_id>/run', methods=['POST'])
@admin_required
def admin_run_user_file(user_id):
    """Chạy file Python của user"""
    try:
        data = request.get_json()
        selected_file = data.get('file')
        
        if not selected_file or not selected_file.endswith('.py'):
            return jsonify({'error': 'File không hợp lệ'}), 400
        
        user_folder = get_user_upload_folder(user_id)
        filepath = os.path.join(user_folder, selected_file)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File không tồn tại'}), 404
        
        # FIX: Chỉ truyền relative path vì đã set cwd
        result = subprocess.run(
            [PYTHON_EXECUTABLE, selected_file],
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

@app.route('/admin/api/user/<int:user_id>/delete_file', methods=['POST'])
@admin_required
def admin_delete_user_file(user_id):
    """Xóa file của user"""
    try:
        data = request.get_json()
        file_path = data.get('file')
        
        if not file_path:
            return jsonify({'error': 'Chưa chọn file'}), 400
        
        user_folder = get_user_upload_folder(user_id)
        full_path = os.path.join(user_folder, file_path)
        
        if not os.path.exists(full_path):
            return jsonify({'error': 'File không tồn tại'}), 404
        
        os.remove(full_path)
        return jsonify({'message': f'Đã xóa file {file_path}'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/admin/api/user/<int:user_id>/clear', methods=['POST'])
@admin_required
def admin_clear_user_files(user_id):
    """Xóa tất cả file của user"""
    try:
        user_folder = get_user_upload_folder(user_id)
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)
        os.makedirs(user_folder, exist_ok=True)
        return jsonify({'message': 'Đã xóa tất cả file của user'}), 200
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/admin/approve/<int:user_id>')
@admin_required
def approve_user(user_id):
    """Phê duyệt tài khoản"""
    try:
        conn = get_db()
        u = conn.execute('SELECT username FROM users WHERE id = ?', 
                         (user_id,)).fetchone()
        
        if not u:
            conn.close()
            return "Không tìm thấy user", 404
        
        conn.execute(
            'UPDATE users SET status = ?, approved_at = CURRENT_TIMESTAMP WHERE id = ?',
            ('approved', user_id)
        )
        conn.commit()
        conn.close()
        
        send_telegram_message(f"✅ Đã phê duyệt tài khoản: <code>{u['username']}</code>")
        
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        return f"Lỗi: {str(e)}", 500

@app.route('/admin/reject/<int:user_id>')
@admin_required
def reject_user(user_id):
    """Từ chối tài khoản"""
    try:
        conn = get_db()
        u = conn.execute('SELECT username FROM users WHERE id = ?', 
                         (user_id,)).fetchone()
        
        if not u:
            conn.close()
            return "Không tìm thấy user", 404
        
        conn.execute('UPDATE users SET status = ? WHERE id = ?', 
                     ('rejected', user_id))
        conn.commit()
        conn.close()
        
        user_folder = get_user_upload_folder(user_id)
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)
        
        send_telegram_message(f"❌ Đã từ chối tài khoản: <code>{u['username']}</code>")
        
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        return f"Lỗi: {str(e)}", 500

@app.route('/admin/api/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Xóa user hoàn toàn"""
    try:
        if user_id == session['user_id']:
            return jsonify({'error': 'Không thể xóa chính mình'}), 400
        
        conn = get_db()
        u = conn.execute('SELECT username FROM users WHERE id = ?', 
                         (user_id,)).fetchone()
        
        if not u:
            conn.close()
            return jsonify({'error': 'Không tìm thấy user'}), 404
        
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        user_folder = get_user_upload_folder(user_id)
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)
        
        send_telegram_message(f"🗑️ Đã xóa user: <code>{u['username']}</code>")
        
        return jsonify({'message': f'Đã xóa user {u["username"]}'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

# ==================== PRIVATE ADMIN LINK ====================

@app.route('/private/admin/<int:user_id>')
@admin_token_required
def private_user_view(user_id):
    """Private link chỉ admin mới xem được - không cần login"""
    try:
        conn = get_db()
        u = conn.execute('SELECT * FROM users WHERE id = ?', 
                         (user_id,)).fetchone()
        conn.close()
        
        if not u:
            abort(404)
        
        user_folder = get_user_upload_folder(user_id)
        files = get_all_files(user_folder)
        
        return render_template(
            'private_user_view.html',
            user=dict(u),
            files=files,
            token=request.args.get('token')
        )
    except Exception as e:
        return f"Lỗi: {str(e)}", 500

@app.route('/private/admin/stats')
@admin_token_required
def private_stats():
    """Private link xem thống kê tổng quan"""
    try:
        conn = get_db()
        
        total_users = conn.execute(
            'SELECT COUNT(*) as count FROM users'
        ).fetchone()['count']
        
        pending_users = conn.execute(
            'SELECT COUNT(*) as count FROM users WHERE status = "pending"'
        ).fetchone()['count']
        
        approved_users = conn.execute(
            'SELECT COUNT(*) as count FROM users WHERE status = "approved"'
        ).fetchone()['count']
        
        rows = conn.execute(
            'SELECT id, username, status, created_at FROM users ORDER BY created_at DESC'
        ).fetchall()
        conn.close()
        
        total_files = 0
        for row in rows:
            user_folder = get_user_upload_folder(row['id'])
            total_files += len(get_all_files(user_folder))
        
        stats = {
            'total_users': total_users,
            'pending_users': pending_users,
            'approved_users': approved_users,
            'total_files': total_files,
            'users': [dict(u) for u in rows]
        }
        
        return render_template(
            'private_stats.html',
            stats=stats,
            token=request.args.get('token')
        )
    except Exception as e:
        return f"Lỗi: {str(e)}", 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
