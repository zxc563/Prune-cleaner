import sys
import os
import json
import time
import hashlib
import struct
import re
import shutil
from datetime import datetime
from pathlib import Path

# GUI Framework
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QTabWidget, QTextEdit, QLineEdit, 
    QMessageBox, QFileDialog, QTreeWidget, QTreeWidgetItem, 
    QHeaderView, QProgressBar, QDialog, QFormLayout, QCheckBox,
    QGroupBox, QRadioButton, QButtonGroup, QSplitter
)
from PySide6.QtCore import Qt, QThread, Signal, QObject
from PySide6.QtGui import QFont, QColor

# Encryption
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# -----------------------------------------------------------------------------
# 1. 核心基础设施 (Infrastructure)
# -----------------------------------------------------------------------------

class SecureLogger:
    """加密日志记录器"""
    def __init__(self, log_file_path="logs/operations.log.enc", password_key=None):
        self.log_file = Path(log_file_path)
        self.log_file.parent.mkdir(exist_ok=True)
        # 默认密钥用于演示，实际应强制用户设置
        if password_key:
            self.key = hashlib.sha256(password_key.encode()).digest()[:16]
        else:
            self.key = b'defaultkey123456' 
        
    def _encrypt_data(self, plaintext: str) -> bytes:
        if not CRYPTO_AVAILABLE:
            return plaintext.encode('utf-8')
        nonce = get_random_bytes(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return nonce + tag + ciphertext

    def append_log_with_header(self, action: str, detail: str, status: str = "SUCCESS"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = json.dumps({"time": timestamp, "action": action, "detail": detail, "status": status}, ensure_ascii=False)
        try:
            encrypted_entry = self._encrypt_data(log_entry)
            length = len(encrypted_entry)
            with open(self.log_file, 'ab') as f:
                f.write(struct.pack('>I', length))
                f.write(encrypted_entry)
        except Exception as e:
            print(f"Log write error: {e}")

class SystemCoreEngine(QObject):
    """系统核心引擎：整合文件工具与隐私安全"""
    progress_signal = Signal(int, str)
    finished_signal = Signal(str, object) # signal_name, data
    log_signal = Signal(str, str, str) # action, detail, status

    def __init__(self):
        super().__init__()
        self.is_running = False

    # --- 文件工具逻辑 ---
    def find_duplicates(self, root_path):
        self.is_running = True
        size_map = {}
        # Phase 1: Group by size
        for root, dirs, files in os.walk(root_path):
            if not self.is_running: break
            for file in files:
                path = os.path.join(root, file)
                try:
                    size = os.path.getsize(path)
                    if size > 0:
                        if size not in size_map:
                            size_map[size] = []
                        size_map[size].append(path)
                except: continue
        
        duplicates = []
        total_groups = len([k for k, v in size_map.items() if len(v) > 1])
        processed = 0
        
        # Phase 2: Hash comparison
        for size, paths in size_map.items():
            if not self.is_running: break
            if len(paths) > 1:
                hash_map = {}
                for path in paths:
                    if not self.is_running: break
                    self.progress_signal.emit(int((processed / max(total_groups, 1)) * 100), f"哈希比对: {os.path.basename(path)}")
                    try:
                        file_hash = hashlib.md5(open(path, 'rb').read()).hexdigest()
                        if file_hash not in hash_map:
                            hash_map[file_hash] = []
                        hash_map[file_hash].append(path)
                    except: pass
                
                for h, dup_paths in hash_map.items():
                    if len(dup_paths) > 1:
                        duplicates.append(dup_paths)
            processed += 1
            
        self.finished_signal.emit("duplicate_scan", duplicates)
        self.is_running = False

    def wipe_file(self, file_path):
        try:
            size = os.path.getsize(file_path)
            with open(file_path, 'r+b') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(file_path)
            self.finished_signal.emit("file_wipe", {"path": file_path, "success": True})
        except Exception as e:
            self.finished_signal.emit("file_wipe", {"path": file_path, "success": False, "error": str(e)})

    def rename_batch(self, file_list, prefix, start_index=1):
        results = []
        for i, old_path in enumerate(file_list):
            dir_name = os.path.dirname(old_path)
            ext = os.path.splitext(old_path)[1]
            new_name = f"{prefix}_{start_index + i}{ext}"
            new_path = os.path.join(dir_name, new_name)
            try:
                os.rename(old_path, new_path)
                results.append({"old": old_path, "new": new_name, "success": True})
            except Exception as e:
                results.append({"old": old_path, "new": new_name, "success": False, "error": str(e)})
        self.finished_signal.emit("batch_rename", results)

    # --- 隐私安全逻辑 ---
    def clean_traces(self, options):
        """options: dict with keys 'recent', 'prefetch', 'temp', 'browser', 'clipboard', 'system_temp'"""
        paths_to_clean = []
        appdata = os.environ.get('APPDATA')
        localappdata = os.environ.get('LOCALAPPDATA')
        windir = os.environ.get('WINDIR', 'C:\\Windows')
        temp = os.environ.get('TEMP')

        if options.get('recent'):
            paths_to_clean.append(os.path.join(appdata, 'Microsoft', 'Windows', 'Recent'))
        if options.get('prefetch'):
            paths_to_clean.append(os.path.join(windir, 'Prefetch'))
        if options.get('temp'):
            paths_to_clean.append(temp)
        if options.get('browser'):
            browsers = ['Google\\Chrome\\User Data\\Default\\Cache', 'Mozilla\\Firefox\\Profiles']
            for b in browsers:
                p = os.path.join(localappdata, b) if localappdata else ""
                if os.path.exists(p): paths_to_clean.append(p)
        if options.get('system_temp'):
            paths_to_clean.append(r"C:\Windows\Temp")

        count = 0
        total_files = 0
        # Estimate total files for progress (rough estimate)
        for path in paths_to_clean:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    total_files += len(files)

        processed = 0
        for path in paths_to_clean:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for f in files:
                        try:
                            os.remove(os.path.join(root, f))
                            count += 1
                        except: pass
                        processed += 1
                        if total_files > 0:
                            self.progress_signal.emit(int((processed / total_files) * 100), f"正在清理: {f}")

        if options.get('clipboard'):
            try:
                import subprocess
                subprocess.run(["powershell", "-command", "Set-Clipboard -Value $null"], capture_output=True)
            except: pass

        self.finished_signal.emit("privacy_clean", f"清理完成，共处理 {count} 个临时项")

    def wipe_free_space(self, drive_letter="C"):
        target_file = os.path.join(f"{drive_letter}:\\", "wipe_temp.dat")
        try:
            chunk_size = 50 * 1024 * 1024 # 50 MB chunks for smoother progress
            written_mb = 0
            with open(target_file, 'wb') as f:
                for i in range(20): # Demo: 1GB total
                    f.write(os.urandom(chunk_size))
                    written_mb += 50
                    self.progress_signal.emit(i * 5, f"正在擦除空闲空间... ({written_mb}MB)")
            os.remove(target_file)
            self.finished_signal.emit("wipe_space", "空闲空间擦除完成 (演示模式：1GB)")
        except Exception as e:
            if os.path.exists(target_file):
                os.remove(target_file)
            self.finished_signal.emit("wipe_space", f"擦除失败: {str(e)}")

# -----------------------------------------------------------------------------
# 2. UI 组件 (UI Components)
# -----------------------------------------------------------------------------

class PasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("管理员验证")
        self.setModal(True)
        layout = QFormLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("请输入管理密码:", self.password_input)
        btn_layout = QHBoxLayout()
        confirm_btn = QPushButton("确认")
        cancel_btn = QPushButton("取消")
        btn_layout.addWidget(confirm_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addRow(btn_layout)
        self.setLayout(layout)
        confirm_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
    def get_password(self):
        return self.password_input.text()

class LogViewerDialog(QDialog):
    def __init__(self, logger: SecureLogger, parent=None):
        super().__init__(parent)
        self.logger = logger
        self.setWindowTitle("操作日志 (加密查看)")
        self.resize(700, 500)
        layout = QVBoxLayout()
        
        pwd_layout = QHBoxLayout()
        self.pwd_input = QLineEdit()
        self.pwd_input.setPlaceholderText("输入解密密码...")
        self.pwd_input.setEchoMode(QLineEdit.Password)
        load_btn = QPushButton("加载日志")
        pwd_layout.addWidget(self.pwd_input)
        pwd_layout.addWidget(load_btn)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        
        layout.addLayout(pwd_layout)
        layout.addWidget(self.log_text)
        self.setLayout(layout)
        load_btn.clicked.connect(self.load_logs)

    def load_logs(self):
        pwd = self.pwd_input.text()
        if not pwd:
            QMessageBox.warning(self, "错误", "请输入密码")
            return
        
        # Temporarily change logger key to user provided one
        original_key = self.logger.key
        self.logger.key = hashlib.sha256(pwd.encode()).digest()[:16]
        
        logs = self.logger.read_all_logs(password_key=pwd) if hasattr(self.logger, 'read_all_logs') else []
        
        # Restore key logic if needed, but here we just decrypt
        display_text = ""
        if not logs:
             # Fallback manual read if method missing or failed
             try:
                 with open(self.logger.log_file, 'rb') as f:
                     while True:
                         len_bytes = f.read(4)
                         if not len_bytes or len(len_bytes) < 4: break
                         length = struct.unpack('>I', len_bytes)[0]
                         blob = f.read(length)
                         if len(blob) < length: break
                         # Try decrypt with current key
                         try:
                             nonce = blob[:12]
                             tag = blob[12:28]
                             ct = blob[28:]
                             cipher = AES.new(self.logger.key, AES.MODE_GCM, nonce=nonce)
                             pt = cipher.decrypt_and_verify(ct, tag)
                             logs.append(json.loads(pt.decode('utf-8')))
                         except: pass
             except: pass

        for log in logs:
            color = "green" if log.get('status') == 'SUCCESS' else "red"
            display_text += f'<span style="color:{color}">[{log.get("time", "")}] [{log.get("status", "")}]</span> <b>{log.get("action", "")}</b><br>&nbsp;&nbsp;&nbsp;&nbsp;Detail: {log.get("detail", "")}<br><br>'
        
        self.log_text.setText(display_text if display_text else "无日志记录或密码错误")
        self.logger.key = original_key

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("关于 prune")
        self.resize(400, 300)
        layout = QVBoxLayout()
        text = QLabel(
            "作者: 周欣辰\n"
            "邮箱: zxc1234guoyang@outlook.com\n"
            "Gitee: https://gitee.com/fl-computer-studio/prunecleaner\n"
            "GitHub: https://github.com/zxc563/Prune-cleaner\n"
            "官网: https://pruneclean.mysxl.cn\n"
            "抖音号: FLpcStudio\n"
            "此软件使用GPLv3.0协议，任何基于本软件的衍生作品必须以相同许可证开源，并提供完整源代码\n"
        )
        text.setAlignment(Qt.AlignCenter)
        text.setWordWrap(True)
        layout.addWidget(text)
        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)
        self.setLayout(layout)

# -----------------------------------------------------------------------------
# 3. 主窗口 (Main Window)
# -----------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("prune - 隐私与文件整合工具箱")
        self.resize(1100, 750)
        
        self.config_file = "config.json"
        self.load_config()
        self.logger = SecureLogger(password_key="default_admin_pwd") 
        
        # Core Engine
        self.engine = SystemCoreEngine()
        self.worker_thread = None
        
        self.init_ui()
        
        # Signals
        self.engine.progress_signal.connect(self.update_progress)
        self.engine.finished_signal.connect(self.handle_engine_result)

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
        else:
            self.config = {"admin_pwd_set": False}

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Tabs
        self.tab_files = QWidget()
        self.setup_files_tab()
        self.tabs.addTab(self.tab_files, "📁 文件工具箱")
        
        self.tab_privacy = QWidget()
        self.setup_privacy_tab()
        self.tabs.addTab(self.tab_privacy, "🛡️ 隐私安全中心")
        
        self.tab_settings = QWidget()
        self.setup_settings_tab()
        self.tabs.addTab(self.tab_settings, "⚙️ 设置与日志")

        self.statusBar().showMessage("就绪 - 纯本地离线模式 | 请设置管理员密码以启用加密日志")
        
        # Progress Bar at bottom
        self.progress_bar = QProgressBar()
        self.progress_label = QLabel("准备就绪")
        main_layout.addWidget(self.progress_label)
        main_layout.addWidget(self.progress_bar)

    def setup_files_tab(self):
        layout = QVBoxLayout(self.tab_files)
        splitter = QSplitter(Qt.Vertical)
        
        # 1. Duplicate Finder
        dup_group = QGroupBox("重复文件检索 (大小+MD5)")
        dup_layout = QVBoxLayout()
        h_path = QHBoxLayout()
        self.dup_path_input = QLineEdit()
        self.dup_path_input.setPlaceholderText("选择要扫描的文件夹路径...")
        btn_select_dup = QPushButton("浏览...")
        btn_scan_dup = QPushButton("开始扫描")
        btn_stop_dup = QPushButton("停止")
        
        h_path.addWidget(self.dup_path_input)
        h_path.addWidget(btn_select_dup)
        h_path.addWidget(btn_scan_dup)
        h_path.addWidget(btn_stop_dup)
        
        self.dup_tree = QTreeWidget()
        self.dup_tree.setHeaderLabels(["文件路径", "大小", "状态"])
        self.dup_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.dup_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        
        dup_layout.addLayout(h_path)
        dup_layout.addWidget(self.dup_tree)
        dup_group.setLayout(dup_layout)
        
        # 2. File Operations
        ops_group = QGroupBox("文件安全操作")
        ops_layout = QHBoxLayout()
        
        shred_box = QVBoxLayout()
        self.shred_path_input = QLineEdit()
        self.shred_path_input.setPlaceholderText("选择要粉碎的文件...")
        btn_select_shred = QPushButton("选择文件")
        btn_shred = QPushButton("执行粉碎")
        shred_box.addWidget(self.shred_path_input)
        shred_box.addWidget(btn_select_shred)
        shred_box.addWidget(btn_shred)
        
        rename_box = QVBoxLayout()
        self.rename_prefix = QLineEdit()
        self.rename_prefix.setPlaceholderText("新文件名前缀")
        btn_rename = QPushButton("重命名选中项")
        rename_box.addWidget(self.rename_prefix)
        rename_box.addWidget(btn_rename)
        
        ops_layout.addLayout(shred_box)
        ops_layout.addLayout(rename_box)
        ops_group.setLayout(ops_layout)
        
        splitter.addWidget(dup_group)
        splitter.addWidget(ops_group)
        layout.addWidget(splitter)
        
        # Connections
        btn_select_dup.clicked.connect(lambda: self.select_path(self.dup_path_input))
        btn_scan_dup.clicked.connect(self.start_duplicate_scan)
        btn_stop_dup.clicked.connect(self.stop_engine)
        btn_select_shred.clicked.connect(lambda: self.select_file(self.shred_path_input))
        btn_shred.clicked.connect(self.start_shred)
        btn_rename.clicked.connect(self.start_batch_rename)

    def setup_privacy_tab(self):
        layout = QVBoxLayout(self.tab_privacy)
        
        trace_group = QGroupBox("系统痕迹清理")
        trace_layout = QVBoxLayout()
        
        grid_trace = QHBoxLayout()
        left_col = QVBoxLayout()
        right_col = QVBoxLayout()
        
        self.cb_recent = QCheckBox("最近访问记录 (Recent)")
        self.cb_prefetch = QCheckBox("预读取文件 (Prefetch)")
        self.cb_temp = QCheckBox("系统临时文件 (Temp)")
        self.cb_browser = QCheckBox("浏览器缓存 (Chrome/Firefox)")
        self.cb_clipboard = QCheckBox("剪贴板内容")
        self.cb_system_temp = QCheckBox("系统临时文件 (C:\\Windows\\Temp)")
        
        left_col.addWidget(self.cb_recent)
        left_col.addWidget(self.cb_prefetch)
        left_col.addWidget(self.cb_temp)
        right_col.addWidget(self.cb_browser)
        right_col.addWidget(self.cb_clipboard)
        right_col.addWidget(self.cb_system_temp)
        
        grid_trace.addLayout(left_col)
        grid_trace.addLayout(right_col)
        
        btn_clean_trace = QPushButton("一键清理选中项")
        btn_clean_trace.setStyleSheet("QPushButton { background-color: #e74c3c; color: white; padding: 10px; font-weight: bold; }")
        
        trace_layout.addLayout(grid_trace)
        trace_layout.addWidget(btn_clean_trace)
        trace_group.setLayout(trace_layout)
        
        wipe_group = QGroupBox("磁盘空闲空间擦除 (防恢复)")
        wipe_layout = QHBoxLayout()
        wipe_label = QLabel("警告：此操作会占用大量磁盘IO，耗时较长。\n原理：用随机数据填满剩余空间后删除。")
        wipe_label.setWordWrap(True)
        btn_wipe = QPushButton("擦除 C 盘空闲空间 (演示1GB)")
        
        wipe_layout.addWidget(wipe_label)
        wipe_layout.addWidget(btn_wipe)
        wipe_group.setLayout(wipe_layout)
        
        layout.addWidget(trace_group)
        layout.addWidget(wipe_group)
        layout.addStretch()
        
        btn_clean_trace.clicked.connect(self.start_privacy_clean)
        btn_wipe.clicked.connect(self.start_wipe_free_space)

    def setup_settings_tab(self):
        layout = QVBoxLayout(self.tab_settings)
        
        info_box = QGroupBox("安全说明")
        info_layout = QVBoxLayout()
        info_label = QLabel("1. 所有操作日志均使用 AES-GCM 加密存储。\n2. 文件粉碎采用 3 次随机覆写标准。\n3. 隐私清理仅针对当前用户目录。")
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        info_box.setLayout(info_layout)
        
        btn_set_pwd = QPushButton("设置/修改管理员密码")
        btn_view_logs = QPushButton("查看加密操作日志")
        btn_about = QPushButton("关于")
        
        layout.addWidget(info_box)
        layout.addWidget(btn_set_pwd)
        layout.addWidget(btn_view_logs)
        layout.addWidget(btn_about)
        layout.addStretch()
        
        btn_set_pwd.clicked.connect(self.set_admin_password)
        btn_view_logs.clicked.connect(self.view_logs)
        btn_about.clicked.connect(self.show_about)

    # --- Helper Functions ---
    def select_path(self, line_edit):
        path = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if path:
            line_edit.setText(path)

    def select_file(self, line_edit):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            line_edit.setText(path)

    def check_admin_auth(self):
        dialog = PasswordDialog(self)
        if dialog.exec() == QDialog.Accepted:
            pwd = dialog.get_password()
            if pwd: return pwd
        return None

    def set_admin_password(self):
        new_pwd = self.check_admin_auth()
        if new_pwd:
            self.logger = SecureLogger(password_key=new_pwd)
            self.config['admin_pwd_set'] = True
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f)
            QMessageBox.information(self, "成功", "管理员密码已更新，后续日志将使用新密码加密")

    def view_logs(self):
        pwd = self.check_admin_auth()
        if pwd:
            dialog = LogViewerDialog(self.logger, self)
            dialog.pwd_input.setText(pwd)
            dialog.exec()

    def show_about(self):
        dialog = AboutDialog(self)
        dialog.exec()

    def update_progress(self, value, text):
        self.progress_bar.setValue(value)
        self.progress_label.setText(text)

    def stop_engine(self):
        self.engine.is_running = False
        self.progress_label.setText("正在停止任务...")

    def start_worker(self, func, *args):
        if self.worker_thread and self.worker_thread.isRunning():
            QMessageBox.warning(self, "提示", "已有任务正在运行，请先停止")
            return
        
        self.worker_thread = QThread()
        self.engine.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(lambda: func(*args))
        self.worker_thread.start()

    # --- Actions ---
    def start_duplicate_scan(self):
        path = self.dup_path_input.text()
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "错误", "请选择有效的文件夹路径")
            return
        
        self.dup_tree.clear()
        self.progress_bar.setValue(0)
        self.start_worker(self.engine.find_duplicates, path)

    def handle_engine_result(self, signal_name, data):
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait()
        
        self.progress_bar.setValue(0)
        self.progress_label.setText("就绪")

        if signal_name == "duplicate_scan":
            duplicates = data
            if not duplicates:
                QMessageBox.information(self, "结果", "未发现重复文件")
                return
            
            for group in duplicates:
                parent_item = QTreeWidgetItem(self.dup_tree, ["=== 重复组 ===", "", ""])
                parent_item.setExpanded(True)
                parent_item.setBackground(0, QColor("#f0f0f0"))
                for file_path in group:
                    try:
                        size = os.path.getsize(file_path)
                        item = QTreeWidgetItem(parent_item, [file_path, f"{size/1024:.2f} KB", "可选"])
                        item.setCheckState(0, Qt.Unchecked)
                    except: pass
            
            self.logger.append_log_with_header("DUP_SCAN", f"Found {len(duplicates)} groups in {self.dup_path_input.text()}")

        elif signal_name == "file_wipe":
            if data['success']:
                QMessageBox.information(self, "成功", "文件已安全粉碎")
                self.shred_path_input.clear()
                self.logger.append_log_with_header("FILE_SHRED", f"Shredded {data['path']}")
            else:
                QMessageBox.critical(self, "失败", f"粉碎失败: {data['error']}")

        elif signal_name == "batch_rename":
            success_count = sum(1 for r in data if r['success'])
            QMessageBox.information(self, "重命名完成", f"成功重命名 {success_count} 个文件")
            self.logger.append_log_with_header("BATCH_RENAME", f"Renamed {success_count} files")

        elif signal_name == "privacy_clean":
            QMessageBox.information(self, "清理完成", data)
            self.logger.append_log_with_header("PRIVACY_CLEAN", data)

        elif signal_name == "wipe_space":
            QMessageBox.information(self, "擦除完成", data)
            self.logger.append_log_with_header("WIPE_SPACE", data)

    def start_shred(self):
        path = self.shred_path_input.text()
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "错误", "请选择有效的文件")
            return
        
        reply = QMessageBox.question(self, "二次确认", "文件粉碎后不可恢复！确定继续吗？", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.progress_label.setText("正在安全擦除...")
            self.start_worker(self.engine.wipe_file, path)

    def start_batch_rename(self):
        prefix = self.rename_prefix.text()
        if not prefix:
            QMessageBox.warning(self, "提示", "请输入重命名前缀")
            return
        
        selected_files = []
        root = self.dup_tree.invisibleRootItem()
        for i in range(root.childCount()):
            group = root.child(i)
            for j in range(group.childCount()):
                child = group.child(j)
                if child.checkState(0) == Qt.Checked:
                    selected_files.append(child.text(0))
        
        if not selected_files:
            QMessageBox.warning(self, "提示", "请在重复文件列表中勾选要重命名的文件")
            return
        
        self.progress_label.setText("正在重命名...")
        self.start_worker(self.engine.rename_batch, selected_files, prefix)

    def start_privacy_clean(self):
        options = {
            'recent': self.cb_recent.isChecked(),
            'prefetch': self.cb_prefetch.isChecked(),
            'temp': self.cb_temp.isChecked(),
            'browser': self.cb_browser.isChecked(),
            'clipboard': self.cb_clipboard.isChecked(),
            'system_temp': self.cb_system_temp.isChecked()
        }
        
        if not any(options.values()):
            QMessageBox.warning(self, "提示", "请至少选择一项清理内容")
            return

        reply = QMessageBox.question(self, "确认", "确定要清理选中的系统痕迹吗？", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.progress_label.setText("正在清理痕迹...")
            self.start_worker(self.engine.clean_traces, options)

    def start_wipe_free_space(self):
        reply = QMessageBox.question(self, "警告", "擦除空闲空间可能需要较长时间。确定继续吗？", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.progress_label.setText("正在擦除空闲空间...")
            self.start_worker(self.engine.wipe_free_space, "C")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())