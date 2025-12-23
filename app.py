from flask import Flask, render_template, request, jsonify, send_file
import os
import subprocess
import zipfile
import shutil
from werkzeug.utils import secure_filename
import json
from datetime import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'py', 'zip'}

def get_python_files(directory):
    """Lấy danh sách tất cả file Python trong thư mục"""
    python_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                rel_path = os.path.relpath(os.path.join(root, file), directory)
                python_files.append(rel_path)
    return sorted(python_files)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Không có file nào được tải lên'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Chưa chọn file'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Chỉ chấp nhận file .py hoặc .zip'}), 400
        
        # Xóa thư mục uploads cũ và tạo mới
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            shutil.rmtree(app.config['UPLOAD_FOLDER'])
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Nếu là file zip, giải nén
        if filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(filepath, 'r') as zip_ref:
                    zip_ref.extractall(app.config['UPLOAD_FOLDER'])
                os.remove(filepath)  # Xóa file zip sau khi giải nén
                message = f'Đã giải nén file {filename} thành công'
            except zipfile.BadZipFile:
                return jsonify({'error': 'File zip không hợp lệ'}), 400
        else:
            message = f'Đã tải lên file {filename} thành công'
        
        # Lấy danh sách file Python
        python_files = get_python_files(app.config['UPLOAD_FOLDER'])
        
        return jsonify({
            'message': message,
            'python_files': python_files
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/get_files', methods=['GET'])
def get_files():
    """Lấy danh sách file Python hiện có"""
    try:
        python_files = get_python_files(app.config['UPLOAD_FOLDER'])
        return jsonify({'python_files': python_files}), 200
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

@app.route('/run', methods=['POST'])
def run_file():
    try:
        data = request.get_json()
        selected_file = data.get('file')
        
        if not selected_file:
            return jsonify({'error': 'Chưa chọn file để chạy'}), 400
        
        if not selected_file.endswith('.py'):
            return jsonify({'error': 'File được chọn không phải là file Python (.py)'}), 400
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], selected_file)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File không tồn tại'}), 404
        
        # Chạy file Python
        result = subprocess.run(
            ['python3.12', filepath],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=app.config['UPLOAD_FOLDER']
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
def install_package():
    try:
        data = request.get_json()
        package_name = data.get('package')
        
        if not package_name:
            return jsonify({'error': 'Chưa nhập tên package'}), 400
        
        # Cài đặt package bằng pip
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
def list_packages():
    """Liệt kê các package đã cài đặt"""
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
def clear_files():
    """Xóa tất cả file đã tải lên"""
    try:
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            shutil.rmtree(app.config['UPLOAD_FOLDER'])
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        return jsonify({'message': 'Đã xóa tất cả file'}), 200
    except Exception as e:
        return jsonify({'error': f'Lỗi: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
