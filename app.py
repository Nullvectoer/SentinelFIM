"""Native PyQt6 File Integrity Monitor. Scans run exclusively in a QThread worker."""
from __future__ import annotations
import base64, hashlib, hmac, json, logging, os, re, secrets, stat, sys, tempfile, threading, time, uuid
from logging.handlers import RotatingFileHandler
import queue, urllib.request, urllib.error
from collections import Counter
from datetime import datetime
from difflib import SequenceMatcher
from html import escape
from pathlib import Path, PurePosixPath
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QRectF, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PyQt6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QGraphicsOpacityEffect,
    QFileDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QMessageBox, QPushButton, QDoubleSpinBox,
    QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
    QStatusBar, QAbstractItemView, QPlainTextEdit, QProgressBar, QTabWidget, QStackedWidget, QTextBrowser,
    QTableWidget, QTableWidgetItem, QHeaderView, QInputDialog, QStyle)
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

CHUNK=1024*1024; TEXT_LIMIT=256*1024; TEXT_BUDGET=24*1024*1024
MAX_FILES=5000; MAX_PROFILES=100; MAX_ALERTS=200; MAX_DB=50*1024*1024
DEFAULT_EXCLUDES='.git,__pycache__,node_modules,.venv,venv'
def process_memory_mb():
    """Return this process's current resident memory in MiB where available."""
    if os.name=='nt':
        try:
            import ctypes
            from ctypes import wintypes
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD),('PeakWorkingSetSize',ctypes.c_size_t),('WorkingSetSize',ctypes.c_size_t),('QuotaPeakPagedPoolUsage',ctypes.c_size_t),('QuotaPagedPoolUsage',ctypes.c_size_t),('QuotaPeakNonPagedPoolUsage',ctypes.c_size_t),('QuotaNonPagedPoolUsage',ctypes.c_size_t),('PagefileUsage',ctypes.c_size_t),('PeakPagefileUsage',ctypes.c_size_t)]
            counters=PROCESS_MEMORY_COUNTERS(); counters.cb=ctypes.sizeof(counters)
            kernel=ctypes.WinDLL('kernel32',use_last_error=True); psapi=ctypes.WinDLL('psapi',use_last_error=True)
            kernel.GetCurrentProcess.restype=ctypes.c_void_p
            psapi.GetProcessMemoryInfo.argtypes=[ctypes.c_void_p,ctypes.POINTER(PROCESS_MEMORY_COUNTERS),wintypes.DWORD]
            psapi.GetProcessMemoryInfo.restype=wintypes.BOOL
            if psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(counters),counters.cb): return counters.WorkingSetSize/1024**2
        except (AttributeError,OSError,ValueError): pass
    try:
        import resource
        value=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return value/1024**2 if sys.platform=='darwin' else value/1024
    except (ImportError,AttributeError,OSError,ValueError): return None
BINARY_EXTENSIONS={'.doc','.docx','.xls','.xlsx','.ppt','.pptx','.odt','.ods','.odp','.pdf','.zip','.7z','.rar','.png','.jpg','.jpeg','.gif','.mp3','.mp4','.exe','.dll','.sys','.com','.msi','.scr','.bin','.dat'}
THEMES={
    'dark':{'void':'#0b0f19','panel':'#111827','input':'#111827','line':'#374151','text':'#f8fafc','muted':'#94a3b8','green':'#10b981','orange':'#f59e0b','red':'#ef4444','purple':'#a855f7','blue':'#3b82f6','accent':'#06b6d4','primary_bg':'#087e8b','primary_text':'#ecfeff','row_alt':'#0c1220','row_hover':'#172033'},
    'cobalt':{'void':'#f1f5f9','panel':'#ffffff','input':'#ffffff','line':'#cbd5e1','text':'#0f172a','muted':'#475569','green':'#16a34a','orange':'#d97706','red':'#dc2626','purple':'#9333ea','blue':'#2563eb','accent':'#0891b2','primary_bg':'#cffafe','primary_text':'#164e63','row_alt':'#f8fafc','row_hover':'#dbeafe'},
    'midnight':{'void':'#071321','panel':'#0d1b2a','input':'#0d1b2a','line':'#1f3b52','text':'#e6f1ff','muted':'#91a9c4','green':'#34d399','orange':'#fbbf24','red':'#fb7185','purple':'#c084fc','blue':'#60a5fa','accent':'#22d3ee','primary_bg':'#164e63','primary_text':'#cffafe','row_alt':'#0a1827','row_hover':'#102a3a'},
    'graphite':{'void':'#141414','panel':'#1d1d1d','input':'#1d1d1d','line':'#373737','text':'#f4f4f5','muted':'#a1a1aa','green':'#4ade80','orange':'#fbbf24','red':'#f87171','purple':'#c084fc','blue':'#60a5fa','accent':'#f59e0b','primary_bg':'#3a2a12','primary_text':'#fde68a','row_alt':'#181818','row_hover':'#2b2b2b'},
    'arctic':{'void':'#eaf1f8','panel':'#ffffff','input':'#ffffff','line':'#cbd5e1','text':'#172033','muted':'#475569','green':'#15803d','orange':'#b45309','red':'#b91c1c','purple':'#7e22ce','blue':'#1d4ed8','accent':'#0369a1','primary_bg':'#e0f2fe','primary_text':'#075985','row_alt':'#f1f5f9','row_hover':'#dbeafe'}
}
LIGHT_THEMES={'cobalt','arctic'}
C=dict(THEMES['dark']); ACTIVE_THEME='dark'
EVENT_COLORS={'CREATED':C['blue'],'TAMPERED':C['red'],'DELETED':C['purple'],'RENAMED':C['blue'],'FALSE ALARM':C['orange'],'MISSED':C['blue']}
APP_QSS_TEMPLATE="""
*{color:#f3f4f6;font-family:'Segoe UI';font-size:9pt}
QMainWindow,QWidget{background:#080c14} QLabel{background:transparent} QFrame#panel,QGroupBox{background:#111827;border:1px solid #1f2937;border-radius:6px} QFrame#sidebar{background:#080c14;border:0;border-right:1px solid #1e293b;border-radius:0}
QLabel#title{color:#f9fafb;font-size:15pt;font-weight:700;letter-spacing:1px} QLabel#panelTitle,QGroupBox::title{color:#e5e7eb;font-size:10pt;font-weight:700;padding:3px 6px}
QLabel#muted{color:#9ca3af} QLabel#dialogTitle{color:#06b6d4;font-size:13pt;font-weight:700;padding:8px 0}
QLabel#errorText{color:#ef4444;font-weight:700} QLineEdit,QComboBox,QDoubleSpinBox,QPlainTextEdit,QTextBrowser{background:#111827;border:1px solid #1e293b;border-radius:6px;padding:5px;selection-background-color:#10b981}
QLineEdit:focus,QComboBox:focus,QSpinBox:focus,QDoubleSpinBox:focus{border:1px solid #06b6d4} QComboBox QAbstractItemView{background:#111827;selection-background-color:#374151}
QPushButton{background:#0e1322;border:1px solid #1e293b;border-radius:6px;padding:6px 8px;font-weight:600} QPushButton:hover{border-color:#06b6d4;background:#12221f}
QPushButton#navButton{background:transparent;border:1px solid transparent;text-align:left;padding:10px 12px;color:#94a3b8} QPushButton#navButton:hover{background:#172033;border-color:#1e293b;color:#f8fafc} QPushButton#navButton:checked{background:#083344;border-color:#0e7490;color:#cffafe} QLabel#alertBadge{background:#dc2626;color:#fff;border-radius:10px;font-weight:800;font-size:8pt;padding:0}
QPushButton#primary{background:#087e8b;border:1px solid #06b6d4;color:#ecfeff} QPushButton#danger{color:#fecaca;border:1px solid #7f1d1d} QPushButton:disabled{color:#64748b}
QTreeWidget,QListWidget{background:#090e19;border:1px solid #1e293b;border-radius:6px;alternate-background-color:#0c1220;outline:0}
QTableWidget{background:#090e19;border:1px solid #1e293b;border-radius:6px;alternate-background-color:#0c1220;gridline-color:#1e293b;outline:0;selection-background-color:#172033;selection-color:#f3f4f6}
QTreeWidget::item,QListWidget::item{padding:4px 5px;border-bottom:1px solid #172033} QTreeWidget::item:selected,QListWidget::item:selected{background:#172033;border-left:2px solid #10b981}
QTableWidget::item{padding:6px 7px;border-bottom:1px solid #1e293b} QTableWidget::item:selected{background:#172033;border-left:2px solid #06b6d4}
QHeaderView::section{background:#111827;color:#cbd5e1;padding:5px;border:0;border-right:1px solid #1e293b;font-weight:700}
QScrollBar:vertical{background:#090e19;width:9px} QScrollBar::handle:vertical{background:#334155;min-height:25px;border-radius:5px}
QStatusBar{background:#0e1322;color:#9ca3af;border-top:1px solid #1e293b}
QLabel#analysisStatus{background:#111827;color:#cbd5e1;padding:7px;border:1px solid #1e293b;border-radius:6px;font-family:Consolas,monospace}
QProgressBar{background:#1f2937;border:0;border-radius:4px;height:7px} QProgressBar::chunk{background:#10b981;border-radius:4px}
QFrame#eventCard{background:#111827;border:1px solid #1e293b;border-radius:6px}
QFrame#inspector{background:#090e19;border:1px solid #1e293b;border-radius:6px}
"""
def set_theme(name):
    global ACTIVE_THEME,APP_QSS
    name=name if name in THEMES else 'dark'; ACTIVE_THEME=name; C.update(THEMES[name])
    EVENT_COLORS.update({'CREATED':C['blue'],'TAMPERED':C['red'],'DELETED':C['purple'],'RENAMED':C['blue'],'FALSE ALARM':C['orange'],'MISSED':C['blue']})
    light=name in LIGHT_THEMES
    mapping={'#f3f4f6':C['text'],'#f9fafb':C['text'],'#e5e7eb':C['text'],'#cbd5e1':C['text'],'#080c14':C['void'],'#070a12':C['void'],'#090e19':C['void'],'#111827':C['input'],'#0e1322':C['panel'],'#1f2937':C['line'],'#1e293b':C['line'],'#172033':C['row_hover'],'#0c1220':C['row_alt'],'#94a3b8':C['muted'],'#9ca3af':C['muted'],'#10b981':C['green'],'#064e3b':C['primary_bg'],'#d1fae5':C['primary_text'],'#ef4444':C['red'],'#f59e0b':C['orange'],'#374151':C['row_hover'],'#12221f':C['row_hover'],'#06b6d4':C['accent'],'#083344':C['primary_bg'],'#0e7490':C['accent'],'#cffafe':C['primary_text'],'#087e8b':C['accent'],'#ecfeff':C['primary_text']}
    # Replace only the original template tokens in one pass. Sequential replace
    # can recolor a new light-theme value again when it matches a later dark token.
    token_pattern=re.compile('|'.join(re.escape(token) for token in sorted(mapping,key=len,reverse=True)))
    APP_QSS=token_pattern.sub(lambda match:mapping[match.group(0)],APP_QSS_TEMPLATE)
    return APP_QSS
APP_QSS=set_theme('dark')

def default_data_dir():
    if os.name=='nt': root=Path(os.environ.get('LOCALAPPDATA',Path.home()/'AppData'/'Local'))
    elif sys.platform=='darwin': root=Path.home()/'Library'/'Application Support'
    else: root=Path(os.environ.get('XDG_DATA_HOME',Path.home()/'.local'/'share'))
    return root/'FileIntegrityMonitor'
def location_pointer_path(): return default_data_dir()/'storage-location.json'
def configured_storage_dir():
    try:
        record=json.loads(location_pointer_path().read_text(encoding='utf-8')); value=record.get('storage_dir') if isinstance(record,dict) else None
        if isinstance(value,str) and value.strip(): return Path(value).expanduser()
    except (OSError,ValueError,UnicodeError): pass
    # Migrate the first preferences-file format if present.
    try:
        old=json.loads((default_data_dir()/'preferences.json').read_text(encoding='utf-8')); value=old.get('storage_dir') if isinstance(old,dict) else None
        if isinstance(value,str) and value.strip(): return Path(value).expanduser()
    except (OSError,ValueError,UnicodeError): pass
    return default_data_dir()
def preferences_path(storage_dir=None): return Path(storage_dir).expanduser()/'preferences.json' if storage_dir else configured_storage_dir()/'preferences.json'
def load_preferences():
    try:
        data=json.loads(preferences_path().read_text(encoding='utf-8'))
        return data if isinstance(data,dict) else {}
    except (OSError,ValueError,UnicodeError):
        # If the selected drive is temporarily unavailable, retain access to
        # the bootstrap settings in the original per-user application folder.
        try:
            data=json.loads((default_data_dir()/'preferences.json').read_text(encoding='utf-8'))
            return data if isinstance(data,dict) else {}
        except (OSError,ValueError,UnicodeError): return {}
def save_preferences(data,storage_dir=None):
    folder=Path(storage_dir).expanduser() if storage_dir else configured_storage_dir(); path=preferences_path(folder); path.parent.mkdir(parents=True,exist_ok=True)
    raw=json.dumps(data,indent=2,ensure_ascii=False).encode('utf-8'); name=None
    try:
        with tempfile.NamedTemporaryFile('wb',dir=path.parent,prefix=path.name+'.',suffix='.tmp',delete=False) as f:
            name=f.name; f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(name,path)
        if os.name!='nt': os.chmod(path,0o600)
    finally:
        if name and os.path.exists(name):
            try: os.unlink(name)
            except OSError: pass
    pointer=location_pointer_path(); pointer.parent.mkdir(parents=True,exist_ok=True); pointer_name=None
    try:
        with tempfile.NamedTemporaryFile('w',encoding='utf-8',dir=pointer.parent,prefix=pointer.name+'.',suffix='.tmp',delete=False) as f:
            pointer_name=f.name; f.write(json.dumps({'storage_dir':str(folder)},indent=2)); f.flush(); os.fsync(f.fileno())
        os.replace(pointer_name,pointer)
    finally:
        if pointer_name and os.path.exists(pointer_name):
            try: os.unlink(pointer_name)
            except OSError: pass
def db_path(storage_dir=None):
    if storage_dir is None: storage_dir=configured_storage_dir()
    if not isinstance(storage_dir,(str,os.PathLike)): storage_dir=None
    folder=Path(storage_dir).expanduser() if storage_dir else default_data_dir()
    return folder/'baselines.json'
def get_saved_api_key():
    """Read an optional Gemini key from the OS credential vault."""
    try:
        import keyring
        return keyring.get_password('FileIntegrityMonitor','gemini-api-key') or ''
    except Exception:
        return ''
def store_api_key(value):
    """Store or remove a Gemini key without writing it into preferences."""
    try:
        import keyring
        if value:
            keyring.set_password('FileIntegrityMonitor','gemini-api-key',value)
        else:
            try: keyring.delete_password('FileIntegrityMonitor','gemini-api-key')
            except keyring.errors.PasswordDeleteError: pass
        return True,''
    except Exception as exc:
        return False,f'{type(exc).__name__}: {exc}'
def app_icon():
    pix=QPixmap(64,64); pix.fill(Qt.GlobalColor.transparent); painter=QPainter(pix); painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen); painter.setBrush(QColor('#0e1322')); painter.drawRoundedRect(2,2,60,60,15,15)
    shield=QPainterPath(); shield.moveTo(32,8); shield.lineTo(51,15); shield.lineTo(49,34); shield.cubicTo(47,45,39,52,32,56); shield.cubicTo(23,51,16,44,15,34); shield.lineTo(13,15); shield.closeSubpath()
    painter.setBrush(QColor(C['green'])); painter.drawPath(shield); painter.setPen(QColor('#062e25')); painter.setFont(QFont('Segoe UI',22,QFont.Weight.Bold)); painter.drawText(pix.rect(),Qt.AlignmentFlag.AlignCenter,'✓'); painter.end(); return QIcon(pix)
def canonical(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
def derive(password,salt): return hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
def sign_state(state,password,salt=None):
    salt=salt or secrets.token_bytes(16); encoded=base64.b64encode(salt).decode('ascii')
    body={'version':1,'active_id':state.get('active_id'),'profiles':state.get('profiles',[]),
          'auth':{'scheme':'HMAC-SHA256-SCRYPT-v1','salt':encoded}}
    sig=hmac.new(derive(password,salt),canonical(body),hashlib.sha256).hexdigest()
    return {**body,'auth':{**body['auth'],'signature':sig}}
def normalize_rel(value):
    s=str(value).replace('\\','/')
    while s.startswith('./'): s=s[2:]
    return s
def valid_rel(value):
    s=normalize_rel(value); p=PurePosixPath(s)
    return bool(s and not p.is_absolute() and '..' not in p.parts and '\x00' not in s)
def validate_db(d):
    if not isinstance(d,dict) or set(d)!={'version','active_id','profiles','auth'} or d['version']!=1: return False
    if not isinstance(d['profiles'],list) or len(d['profiles'])>MAX_PROFILES: return False
    a=d['auth']
    if not isinstance(a,dict) or set(a)!={'scheme','salt','signature'} or a['scheme']!='HMAC-SHA256-SCRYPT-v1': return False
    try: salt=base64.b64decode(a['salt'],validate=True)
    except (ValueError,TypeError): return False
    if len(salt)!=16 or not isinstance(a['signature'],str) or not re.fullmatch('[0-9a-f]{64}',a['signature']): return False
    ids=set()
    for p in d['profiles']:
        required={'id','label','target','created','recursive','max_bytes','excludes','files'}
        if not isinstance(p,dict) or not required.issubset(p): return False
        if (not isinstance(p['id'],str) or not p['id'] or p['id'] in ids or not isinstance(p['target'],str)
            or not isinstance(p['label'],str) or not isinstance(p['created'],str) or not isinstance(p['recursive'],bool)
            or not isinstance(p['max_bytes'],int) or p['max_bytes']<1 or not isinstance(p['excludes'],list)
            or not all(isinstance(x,str) for x in p['excludes']) or not isinstance(p['files'],dict) or len(p['files'])>MAX_FILES): return False
        ids.add(p['id'])
        for rel,r in p['files'].items():
            if not valid_rel(rel) or not isinstance(r,dict) or not isinstance(r.get('size'),int) or r['size']<0: return False
            if r.get('status') not in ('hashed','excluded','locked'): return False
            if not isinstance(r.get('mtime_ns'),(int,type(None))) or not isinstance(r.get('created_ns'),(int,type(None))): return False
            for k,n in (('sha256',64),('sha512',128)):
                h=r.get(k)
                if h is not None and (not isinstance(h,str) or not re.fullmatch(rf'[0-9a-f]{{{n}}}',h)): return False
                if r['status']=='hashed' and h is None: return False
    active=d['active_id']
    return active is None or (isinstance(active,str) and active in ids)
def verify_signed(d,password):
    if not validate_db(d): return None,'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED.'
    salt=base64.b64decode(d['auth']['salt'],validate=True)
    body={'version':1,'active_id':d['active_id'],'profiles':d['profiles'],
          'auth':{'scheme':d['auth']['scheme'],'salt':d['auth']['salt']}}
    expected=hmac.new(derive(password,salt),canonical(body),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,d['auth']['signature']):
        return None,'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED. Password mismatch or database tampering detected.'
    return {'active_id':d['active_id'],'profiles':d['profiles']},None

def import_legacy(d,password):
    if not isinstance(d,dict) or not isinstance(d.get('items'),list): return None,'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED.'
    body={'items':d['items'],'active':d.get('active')}
    chk=hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()
    if not hmac.compare_digest(str(d.get('checksum','')),chk): return None,'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED.'
    old=d.get('auth')
    if old:
        try:
            salt=base64.b64decode(old['salt'],validate=True)
            oldbody=json.dumps({'items':d['items'],'active':d.get('active'),'checksum':d['checksum']},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
            sig=hmac.new(derive(password,salt),oldbody,hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig,old.get('signature','')): return None,'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED. Password mismatch or legacy database tampering.'
        except (KeyError,ValueError,TypeError): return None,'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED.'
    profiles=[]
    for item in d['items']:
        if not isinstance(item,dict) or not isinstance(item.get('files'),dict): return None,'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED.'
        files={}
        for rel,r in item['files'].items():
            if not valid_rel(rel) or not isinstance(r,dict): return None,'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED.'
            old_status=r.get('status','locked')
            status={'skipped':'excluded','unreadable':'locked'}.get(old_status,old_status)
            if status not in ('hashed','excluded','locked'): status='locked'
            files[normalize_rel(rel)]={'size':int(r.get('size',0)),'mtime_ns':int(r['mtime']) if isinstance(r.get('mtime'),(int,float)) else None,'created_ns':int(r['created_ns']) if isinstance(r.get('created_ns'),(int,float)) else None,
                'sha256':r.get('sha256'),'sha512':r.get('sha512'),'status':status}
        profiles.append({'id':str(item.get('id') or uuid.uuid4().hex),'label':str(item.get('label','Imported profile')),
            'target':str(item.get('path','')),'created':str(item.get('created',datetime.now().isoformat(timespec='seconds'))),
            'recursive':bool(item.get('recursive',True)),'max_bytes':max(1,int(float(item.get('max_gb',1))*(1024**3))),
            'excludes':DEFAULT_EXCLUDES.split(','),'files':files})
    active=next((p['id'] for p in profiles if p['id']==d.get('active')),profiles[0]['id'] if profiles else None)
    return {'active_id':active,'profiles':profiles[:MAX_PROFILES]},None

def load_db(path,password):
    if not path.exists():
        return ({'active_id':None,'profiles':[]},None,False) if password else (None,'setup',False)
    try:
        if path.stat().st_size>MAX_DB: return None,'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED (size limit).',False
        d=json.loads(path.read_text(encoding='utf-8'))
        if isinstance(d,dict) and d.get('version')==1:
            if password is None: return None,'unlock',False
            state,error=verify_signed(d,password); return state,error,False
        if password is None: return None,'migrate',True
        state,error=import_legacy(d,password); return state,error,True
    except (OSError,UnicodeError,ValueError,TypeError,OverflowError) as e:
        return None,f'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED ({type(e).__name__}).',False

def initial_baseline_for_target(profiles,target):
    """Return the newest saved automatic baseline for this normalized target."""
    try: key=os.path.normcase(os.path.abspath(target))
    except (OSError,TypeError,ValueError): return None
    matches=[]
    for profile in profiles or ():
        if not str(profile.get('label','')).startswith('Initial baseline · ') or not profile.get('target'): continue
        try: same=os.path.normcase(os.path.abspath(profile.get('target','')))==key
        except (OSError,TypeError,ValueError): same=False
        if same: matches.append(profile)
    return max(matches,key=lambda item:str(item.get('created',''))) if matches else None

def save_db(path,state,password):
    data=sign_state(state,password)
    if not validate_db(data): raise ValueError('Baseline database failed structural validation')
    raw=json.dumps(data,indent=2,ensure_ascii=False).encode('utf-8'); path.parent.mkdir(parents=True,exist_ok=True)
    name=None
    try:
        with tempfile.NamedTemporaryFile('wb',dir=path.parent,prefix=path.name+'.',suffix='.tmp',delete=False) as f:
            name=f.name; f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(name,path)
        if os.name!='nt': os.chmod(path,0o600); os.chmod(path.parent,0o700)
    finally:
        if name and os.path.exists(name):
            try: os.unlink(name)
            except OSError: pass

class KeyDialog(QDialog):
    """Password gate; dashboard is not constructed unless database auth succeeds."""
    def __init__(self,path):
        super().__init__(); self.path=path; self.state=None; self.password=''; self.migrated=False
        self.setWindowTitle('FIM · Baseline database security'); self.setMinimumWidth(480)
        layout=QVBoxLayout(self); title=QLabel('BASELINE DATABASE SECURITY'); title.setObjectName('dialogTitle'); layout.addWidget(title)
        exists=path.exists(); self.mode='unlock' if exists else 'setup'; legacy=False
        if exists:
            try: probe=json.loads(path.read_text(encoding='utf-8')); legacy=not(isinstance(probe,dict) and probe.get('version')==1)
            except (OSError,ValueError,UnicodeError): self.mode='fatal'
            if legacy: self.mode='migrate'
        text=('Create a key (12+ characters) for this local database. It is never stored; enter it again when the app opens.' if self.mode=='setup'
            else 'Legacy database found. Its checksum is not a security signature. Enter a key to validate and migrate it.' if self.mode=='migrate'
            else 'Enter the database key to authenticate baseline history. The dashboard stays locked until it verifies.' if self.mode=='unlock'
            else 'FATAL: LOCAL BASELINE DATABASE INTEGRITY COMPROMISED.')
        msg=QLabel(text); msg.setWordWrap(True); layout.addWidget(msg)
        form=QFormLayout(); self.key=QLineEdit(); self.key.setEchoMode(QLineEdit.EchoMode.Password); self.key.setPlaceholderText('Database key · 12+ characters'); form.addRow('Password key',self.key)
        self.confirm=QLineEdit(); self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        if self.mode in ('setup','migrate'): self.confirm.setPlaceholderText('Repeat key'); form.addRow('Confirm key',self.confirm)
        layout.addLayout(form); self.error=QLabel(''); self.error.setObjectName('errorText'); self.error.setWordWrap(True); layout.addWidget(self.error)
        buttons=QDialogButtonBox(); self.go=buttons.addButton('Initialize / Unlock',QDialogButtonBox.ButtonRole.AcceptRole); cancel=buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.go.clicked.connect(self.unlock); cancel.clicked.connect(self.reject); layout.addWidget(buttons); self.setStyleSheet(APP_QSS)
        self.forgot=QPushButton('Forgot password? Reset saved baselines…'); self.forgot.setVisible(exists); self.forgot.clicked.connect(self.forgot_password); layout.addWidget(self.forgot)
        if self.mode=='fatal': self.key.setEnabled(False); self.go.setEnabled(False); self.error.setText(text)
    def unlock(self):
        password=self.key.text()
        if len(password)<12: self.error.setText('Use at least 12 characters for the database key.'); return
        if self.mode in ('setup','migrate') and password!=self.confirm.text(): self.error.setText('Key confirmation does not match.'); return
        state,error,migrated=load_db(self.path,password)
        if error:
            warning=QMessageBox(self); warning.setIcon(QMessageBox.Icon.Critical); warning.setWindowTitle('CRITICAL REASON: BASELINE DATA MODIFIED ON DISK.'); warning.setText('CRITICAL REASON: BASELINE DATA MODIFIED ON DISK.'); warning.setInformativeText(error+'\n\nThe dashboard remains locked until the baseline database can be authenticated.'); warning.setStandardButtons(QMessageBox.StandardButton.Close); warning.setWindowState(warning.windowState()|Qt.WindowState.WindowFullScreen); warning.exec(); self.error.setText(error); return
        if state is None: self.error.setText('Database could not be authenticated.'); return
        try: save_db(self.path,state,password)
        except (OSError,ValueError) as e: self.error.setText(f'Could not securely save baseline storage: {e}'); return
        self.state,self.password,self.migrated=state,password,migrated; self.accept()
    def forgot_password(self):
        answer=QMessageBox.warning(self,'Reset baseline password','A forgotten password cannot be recovered. Resetting creates a new, empty baseline database; your old database is preserved as a locked backup and its baselines will not be available in this session. Continue?',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.Cancel,QMessageBox.StandardButton.Cancel)
        if answer!=QMessageBox.StandardButton.Yes: return
        new,ok=QInputDialog.getText(self,'Create a new database password','New password (at least 12 characters):',QLineEdit.EchoMode.Password)
        if not ok: return
        confirm,ok=QInputDialog.getText(self,'Confirm database password','Repeat the new password:',QLineEdit.EchoMode.Password)
        if not ok: return
        if len(new)<12 or new!=confirm: self.error.setText('Use at least 12 characters and make both entries match.'); return
        backup=self.path.with_name(self.path.name+'.locked-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'.bak')
        try:
            os.replace(self.path,backup)
            fresh={'active_id':None,'profiles':[]}; save_db(self.path,fresh,new)
        except (OSError,ValueError) as exc:
            try:
                if backup.exists() and not self.path.exists(): os.replace(backup,self.path)
            except OSError: pass
            self.error.setText(f'Password reset failed; the old database was preserved. {exc}'); return
        self.state,self.password,self.migrated=fresh,new,False; self.accept()

def is_excluded(rel, names):
    parts=PurePosixPath(rel).parts
    return any(part in names for part in parts)
def scan_file(path, rel, max_bytes):
    try:
        entry=path.lstat()
        if stat.S_ISLNK(entry.st_mode):
            return {'size':int(entry.st_size),'mtime_ns':entry.st_mtime_ns,'created_ns':getattr(entry,'st_ctime_ns',None),'status':'locked','sha256':None,'sha512':None,'_text':None,'_error':'Symbolic link was not followed; choose the target explicitly if it should be monitored.'}
        before=path.stat()
        if not stat.S_ISREG(before.st_mode): return {'size':int(before.st_size),'mtime_ns':before.st_mtime_ns,'created_ns':getattr(before,'st_ctime_ns',None),'status':'locked','sha256':None,'sha512':None,'_text':None,'_error':'Not a regular file'}
        if before.st_size>max_bytes: return {'size':int(before.st_size),'mtime_ns':before.st_mtime_ns,'created_ns':getattr(before,'st_ctime_ns',None),'status':'excluded','sha256':None,'sha512':None,'_text':None,'_error':None}
        a=hashlib.sha256(); b=hashlib.sha512(); textbuf=bytearray(); text_ok=True; sha256_seconds=sha512_seconds=0.0
        with path.open('rb') as f:
            opened=os.fstat(f.fileno()); current_entry=path.lstat()
            same_identity=(not before.st_ino or not opened.st_ino or (before.st_dev,before.st_ino)==(opened.st_dev,opened.st_ino))
            if stat.S_ISLNK(current_entry.st_mode) or not stat.S_ISREG(opened.st_mode) or not same_identity:
                return {'size':int(before.st_size),'mtime_ns':before.st_mtime_ns,'created_ns':getattr(before,'st_ctime_ns',None),'status':'locked','sha256':None,'sha512':None,'_text':None,'_error':'File path changed or became a symbolic link before it could be read; retrying next scan.'}
            while True:
                block=f.read(CHUNK)
                if not block: break
                tick=time.perf_counter(); a.update(block); sha256_seconds+=time.perf_counter()-tick
                tick=time.perf_counter(); b.update(block); sha512_seconds+=time.perf_counter()-tick
                if text_ok:
                    if len(textbuf)+len(block)<=TEXT_LIMIT: textbuf.extend(block)
                    else: text_ok=False; textbuf.clear()
            opened_after=os.fstat(f.fileno())
        after=path.stat(); final_entry=path.lstat()
        identity_stable=(not opened.st_ino or not opened_after.st_ino or (opened.st_dev,opened.st_ino)==(opened_after.st_dev,opened_after.st_ino))
        path_still_same=(not opened.st_ino or not final_entry.st_ino or (opened.st_dev,opened.st_ino)==(final_entry.st_dev,final_entry.st_ino))
        if stat.S_ISLNK(final_entry.st_mode) or not identity_stable or not path_still_same:
            return {'size':int(opened_after.st_size),'mtime_ns':opened_after.st_mtime_ns,'created_ns':getattr(opened_after,'st_ctime_ns',None),'status':'locked','sha256':None,'sha512':None,'_text':None,'_error':'File path changed or became a symbolic link while it was being read; retrying next scan.'}
        if before.st_size!=opened_after.st_size or before.st_mtime_ns!=opened_after.st_mtime_ns:
            return {'size':int(opened_after.st_size),'mtime_ns':opened_after.st_mtime_ns,'created_ns':getattr(opened_after,'st_ctime_ns',None),'status':'locked','sha256':None,'sha512':None,'_text':None,'_error':'File changed while it was being read; retrying next scan'}
        raw=bytes(textbuf) if text_ok else None
        if raw is not None:
            try: raw.decode('utf-8')
            except UnicodeDecodeError: raw=None
        return {'size':int(after.st_size),'mtime_ns':after.st_mtime_ns,'created_ns':getattr(after,'st_ctime_ns',None),'status':'hashed','sha256':a.hexdigest(),'sha512':b.hexdigest(),'_text':raw,'_error':None,'_sha256_seconds':sha256_seconds,'_sha512_seconds':sha512_seconds}
    except (OSError,PermissionError) as e:
        try: s=path.stat(); size=int(s.st_size); mt=s.st_mtime_ns; ct=getattr(s,'st_ctime_ns',None)
        except OSError: size=0; mt=None; ct=None
        return {'size':size,'mtime_ns':mt,'created_ns':ct,'status':'locked','sha256':None,'sha512':None,'_text':None,'_error':f'{type(e).__name__}: {e}'}
def scan_tree(target,recursive,max_bytes,excludes):
    root=Path(target); files={}; directories=set(); directory_info={}; issues=[]; names={x.strip() for x in excludes if x.strip()}; text_budget=TEXT_BUDGET; hash_stats={'sha256_seconds':0.0,'sha512_seconds':0.0,'bytes':0}
    try: absolute_target=str(root.resolve(strict=False))
    except (OSError,RuntimeError): absolute_target=os.path.abspath(str(root))
    if root.is_symlink():
        return {'files':files,'directories':directories,'directory_info':directory_info,'absolute_target':absolute_target,'hash_stats':hash_stats,'issues':[{'path':'.','error':'Selected target is a symbolic link and was not followed. Choose its resolved target explicitly if it should be monitored.'}]}
    try:
        root_stat=root.stat()
        directory_info['.']={'size':int(root_stat.st_size),'mtime_ns':root_stat.st_mtime_ns,'created_ns':getattr(root_stat,'st_ctime_ns',None),'kind':'Folder' if root.is_dir() else 'File'}
        if root.is_file():
            rel=root.name; rec=scan_file(root,rel,max_bytes); files[rel]=rec
            if rec.get('status')=='hashed':
                hash_stats['bytes']+=rec['size']; hash_stats['sha256_seconds']+=rec.get('_sha256_seconds',0); hash_stats['sha512_seconds']+=rec.get('_sha512_seconds',0)
            if rec['_error']: issues.append({'path':rel,'error':rec['_error']})
        elif root.is_dir():
            def onerror(error):
                filename=getattr(error,'filename',None) or str(root)
                try: rel=normalize_rel(Path(filename).relative_to(root).as_posix())
                except (ValueError,OSError): rel='.'
                issues.append({'path':rel,'error':f'{type(error).__name__}: {error}'})
            for current,dirs,names_in in os.walk(root,topdown=True,onerror=onerror,followlinks=False):
                base=Path(current)
                try: rel_dir='.' if base==root else normalize_rel(base.relative_to(root).as_posix())
                except ValueError: rel_dir='.'
                directories.add(rel_dir)
                try:
                    folder_stat=base.stat(); directory_info[rel_dir]={'size':int(folder_stat.st_size),'mtime_ns':folder_stat.st_mtime_ns,'created_ns':getattr(folder_stat,'st_ctime_ns',None),'kind':'Folder'}
                except OSError as e: issues.append({'path':rel_dir,'error':f'{type(e).__name__}: {e}'})
                kept=[]
                for d in sorted(dirs):
                    child=base/d
                    try: rel=normalize_rel(child.relative_to(root).as_posix())
                    except ValueError: rel=normalize_rel(d)
                    if is_excluded(rel,names): continue
                    if child.is_symlink():
                        issues.append({'path':rel,'error':'Symbolic-link directory was not followed; its target is outside the scanned folder scope.'})
                        continue
                    directories.add(rel)
                    try:
                        folder_stat=child.stat(); directory_info[rel]={'size':int(folder_stat.st_size),'mtime_ns':folder_stat.st_mtime_ns,'created_ns':getattr(folder_stat,'st_ctime_ns',None),'kind':'Folder'}
                    except OSError as e: issues.append({'path':rel,'error':f'{type(e).__name__}: {e}'})
                    if recursive: kept.append(d)
                    else:
                        pass
                dirs[:]=kept
                for name in sorted(names_in):
                    path=base/name
                    try: rel=normalize_rel(path.relative_to(root).as_posix())
                    except ValueError: continue
                    if is_excluded(rel,names): continue
                    if len(files)>=MAX_FILES:
                        issues.append({'path':rel,'error':f'File limit reached ({MAX_FILES}); remaining entries were not scanned.'}); dirs[:]=[]; break
                    rec=scan_file(path,rel,max_bytes)
                    if rec['_text'] is not None:
                        if len(rec['_text'])<=text_budget: text_budget-=len(rec['_text'])
                        else: rec['_text']=None
                    if rec['_error']: issues.append({'path':rel,'error':rec['_error']})
                    files[rel]=rec
                    if rec.get('status')=='hashed':
                        hash_stats['bytes']+=rec['size']; hash_stats['sha256_seconds']+=rec.get('_sha256_seconds',0); hash_stats['sha512_seconds']+=rec.get('_sha512_seconds',0)
        else: issues.append({'path':str(root),'error':'Target is not a file or folder.'})
    except OSError as e: issues.append({'path':str(root),'error':f'{type(e).__name__}: {e}'})
    return {'files':files,'directories':directories,'directory_info':directory_info,'absolute_target':absolute_target,'hash_stats':hash_stats,'issues':issues}
def retain_unavailable(previous,current,issues):
    # Keep prior entries beneath failed nodes so temporary access errors never become false deletions.
    paths=[x['path'] for x in issues]
    for rel,rec in previous.items():
        if rel in current: continue
        if any(p=='.' or rel==p or rel.startswith(p.rstrip('/')+'/') for p in paths):
            held=dict(rec); held['_error']='Retained from last successful scan because this location is unavailable'; current[rel]=held
    return current
def retain_unavailable_directories(previous,current,previous_info,issues,current_info):
    """Keep last-known folder nodes visible below paths that failed to enumerate."""
    failed=[issue.get('path','.') for issue in issues]
    for rel in previous:
        if rel in current: continue
        if any(path=='.' or rel==path or rel.startswith(path.rstrip('/')+'/') for path in failed):
            current.add(rel)
            if rel in previous_info: current_info.setdefault(rel,previous_info[rel])
    return current
def changed_lines(old,new):
    if old is None or new is None: return None
    old_text=old.decode('utf-8',errors='replace'); new_text=new.decode('utf-8',errors='replace'); a=old_text.splitlines(); b=new_text.splitlines()
    matcher=SequenceMatcher(a=a,b=b,autojunk=False); removed=added=0; removed_snippet=[]; added_snippet=[]
    for tag,i1,i2,j1,j2 in matcher.get_opcodes():
        if tag in ('replace','delete'):
            removed+=i2-i1; removed_snippet.extend(x[:180] for x in a[i1:i2])
        if tag in ('replace','insert'):
            added+=j2-j1; added_snippet.extend(x[:180] for x in b[j1:j2])
    return {'removed':removed,'added':added,'old_chars':len(old_text),'new_chars':len(new_text),'char_delta':len(new_text)-len(old_text),'removed_lines':removed_snippet[:8],'added_lines':added_snippet[:8]}
def public_record(record): return {k:v for k,v in record.items() if not k.startswith('_')}
def update_alert_lifecycle(detected,seen,acknowledged):
    """Return current and newly active alerts, releasing signatures once resolved."""
    active={tuple(event['signature']) for event in detected}
    seen.intersection_update(active)
    acknowledged.intersection_update(active)
    visible=[]; fresh=[]
    for event in detected:
        signature=tuple(event['signature'])
        if signature in acknowledged: continue
        visible.append(event)
        if signature not in seen:
            fresh.append(event); seen.add(signature)
    return visible,fresh
def detect_events(baseline,current,issues,methods):
    events=[]; before=baseline.get('files',{}) if baseline else {}; after=current.get('files',{})
    failed=[x['path'] for x in issues]
    keys=sorted(set(before)|set(after))
    for rel in keys:
        old=before.get(rel); new=after.get(rel)
        if old and new and str(new.get('_error') or '').startswith('Retained from last successful'): continue
        if old and not new:
            if any(p=='.' or rel==p or rel.startswith(p.rstrip('/')+'/') for p in failed): continue
            if old.get('status')!='hashed': continue
            typ='DELETED'
        elif not old and new:
            if new.get('status')!='hashed': continue
            typ='CREATED'
        elif old and new:
            if old.get('status')!='hashed' or new.get('status')!='hashed': continue
            if all(old.get(k)==new.get(k) for k in methods): continue
            typ='TAMPERED'
        else: continue
        diff=changed_lines(old.get('_text') if old else None,new.get('_text') if new else None)
        if typ=='TAMPERED' and PurePosixPath(rel).suffix.lower() in BINARY_EXTENSIONS: detail='Confidential Binary Signature Shift Identified · binary file signature changed.'
        elif typ=='TAMPERED' and diff is not None: detail=f"Content changed: {diff['removed']} line(s) removed, {diff['added']} line(s) added."
        elif typ=='TAMPERED': detail='Cryptographic hash changed. Text diff is unavailable (file may be binary, large, or outside the text cache).'
        elif typ=='CREATED': detail='New file appeared in the monitored folder.'
        else: detail='File is missing from the monitored folder.'
        events.append({'id':uuid.uuid4().hex,'type':typ,'path':rel,'time':datetime.now().astimezone().isoformat(timespec='seconds'),'detail':detail,'old_size':old.get('size') if old else None,'new_size':new.get('size') if new else None,'diff':diff,'old_hash':old.get('sha256') if old else None,'new_hash':new.get('sha256') if new else None,'old_sha512':old.get('sha512') if old else None,'new_sha512':new.get('sha512') if new else None,'signature':(typ,rel,(new or old or {}).get('sha256'),(new or old or {}).get('size'))})
    # Pair only unambiguous moves whose complete SHA-256/SHA-512 footprint and size match.
    removed={}; added={}
    for ev in events:
        if ev['type']=='DELETED' and ev['old_hash'] and ev['old_sha512']: removed.setdefault((ev['old_hash'],ev['old_sha512'],ev.get('old_size')),[]).append(ev)
        if ev['type']=='CREATED' and ev['new_hash'] and ev['new_sha512']: added.setdefault((ev['new_hash'],ev['new_sha512'],ev.get('new_size')),[]).append(ev)
    paired=set(); renames=[]
    for digest,old_events in removed.items():
        new_events=added.get(digest,[])
        if len(old_events)==len(new_events)==1:
            old_ev,new_ev=old_events[0],new_events[0]
            old_ev['type']='RENAMED'; old_ev['old_path']=old_ev['path']; old_ev['path']=new_ev['path']; old_ev['new_path']=new_ev['path']
            old_ev['new_size']=new_ev['new_size']; old_ev['new_hash']=new_ev['new_hash']; old_ev['new_sha512']=new_ev['new_sha512']; old_ev['detail']=f"Asset moved or renamed from {old_ev['old_path']} to {new_ev['path']}."
            old_ev['signature']=('RENAMED',old_ev['old_path'],new_ev['path'],digest)
            paired.update((old_ev['id'],new_ev['id'])); renames.append(old_ev)
    events=[e for e in events if e['id'] not in paired]+renames
    return events

def classify_inventory_records(baseline_files,current_files,events,issues,methods,scan_valid=True):
    """Build one authoritative inventory row per relative path from scan and baseline data."""
    has_baseline=baseline_files is not None; before=baseline_files or {}; after=current_files or {}; event_by_path={}
    for event in events or []:
        if event.get('path'): event_by_path[event['path']]=event
        if event.get('old_path'): event_by_path[event['old_path']]=event
    failed=[]
    for issue in issues or []:
        path=str(issue.get('path') or '.').replace('\\','/').strip('/') or '.'
        message=str(issue.get('error') or '')
        # Watchdog availability is not a failed content scan; periodic scans still verify files.
        if 'watcher unavailable' in message.lower(): continue
        failed.append((path,message))
    def failure_for(rel):
        for path,message in failed:
            if path=='.' or rel==path or rel.startswith(path.rstrip('/')+'/'):
                return message or 'The filesystem scan could not verify this location.'
        return None
    def digest_comparison(old,new):
        selected=tuple(methods or ('sha256','sha512'))
        if not selected or any(not old.get(method) or not new.get(method) for method in selected): return None
        return all(old.get(method)==new.get(method) for method in selected)
    rows={}
    for rel,record in after.items():
        rel=str(rel).replace('\\','/')
        old=before.get(rel); event=event_by_path.get(rel)
        error=record.get('_error') or failure_for(rel)
        if not scan_valid: status='SCAN ERROR'; error='Waiting for a successful scan of the selected target.'
        elif error or record.get('status')!='hashed':
            status='SCAN ERROR'
            error=error or ('File was excluded or skipped and was not verified.' if record.get('status') in ('excluded','skipped') else 'File could not be hashed reliably.')
        elif not has_baseline: status='SCAN ERROR'; error='No saved baseline is available for integrity comparison.'
        elif event and event.get('type')=='RENAMED': status='RENAMED'
        elif not old: status='CREATED'
        elif old.get('status')!='hashed': status='SCAN ERROR'; error='The saved baseline has no verified hash for this file.'
        elif digest_comparison(old,record) is None: status='SCAN ERROR'; error='A selected digest is missing from the current scan or saved baseline.'
        elif not digest_comparison(old,record): status='TAMPERED'
        else: status='UNCHANGED'
        rows[rel]={'relative':rel,'status':status,'record':record,'event':event,'error':error}
    for rel,record in before.items():
        rel=str(rel).replace('\\','/')
        if rel in rows or record.get('status')!='hashed': continue
        # A paired rename is represented once, at its current path.
        event=event_by_path.get(rel)
        if event and event.get('type')=='RENAMED': continue
        error='Waiting for a successful scan of the selected target.' if not scan_valid else failure_for(rel)
        if error:
            rows[rel]={'relative':rel,'status':'SCAN ERROR','record':record,'event':None,'error':error}
        else:
            rows[rel]={'relative':rel,'status':'DELETED','record':record,'event':event,'error':None}
    return rows

def baseline_integrity_percentage(baseline_files,current_files,events,issues,methods,scan_valid=True):
    """Return baseline match rate for verified entries only.

    Numerator is UNCHANGED rows. Denominator is verified UNCHANGED, TAMPERED,
    DELETED, CREATED, and RENAMED rows from the latest successful scan. SCAN
    ERROR, excluded, skipped, and otherwise unverified files are omitted. This
    is an observed baseline match rate, not a security guarantee.
    """
    if baseline_files is None or not scan_valid: return None
    rows=classify_inventory_records(baseline_files,current_files,events,issues,methods,scan_valid)
    verified={'UNCHANGED','TAMPERED','DELETED','CREATED','RENAMED'}
    states=[row.get('status') for row in rows.values() if row.get('status') in verified]
    if not states: return None
    return 100.0*sum(state=='UNCHANGED' for state in states)/len(states)

def display_timestamp(value):
    """Format stored ISO timestamps as local 12-hour time for the UI."""
    try:
        parsed=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        if parsed.tzinfo is None: parsed=parsed.astimezone()
        return parsed.astimezone().strftime('%b %d, %Y · %I:%M:%S %p')
    except (TypeError,ValueError,OverflowError): return str(value or '—')

class _WatchQueueHandler(FileSystemEventHandler):
    """Pass native filesystem notifications to the scanner without doing file I/O here."""
    def __init__(self,events,wake,root,recursive,file_target=None): super().__init__(); self.events=events; self.wake=wake; self.root=os.path.normcase(os.path.realpath(os.path.abspath(root))); self.recursive=recursive; self.file_target=os.path.normcase(os.path.realpath(os.path.abspath(file_target))) if file_target else None
    def _in_scope(self,path):
        absolute=os.path.normcase(os.path.realpath(os.path.abspath(path)))
        if self.file_target: return absolute==self.file_target
        try:
            inside=os.path.commonpath((self.root,absolute))==self.root
            return inside and (self.recursive or os.path.dirname(absolute)==self.root)
        except (ValueError,OSError): return False
    def on_any_event(self,event):
        if event.event_type not in ('created','modified','deleted','moved'): return
        if not self._in_scope(event.src_path) and not self._in_scope(getattr(event,'dest_path','') or event.src_path): return
        self.events.put({'type':event.event_type,'source':str(event.src_path),'destination':str(getattr(event,'dest_path','') or ''),'directory':bool(event.is_directory),'time':time.time()})
        self.wake.set()

class MonitorWorker(QThread):
    scan_ready=pyqtSignal(object)
    def __init__(self):
        super().__init__(); self._lock=threading.RLock(); self._stop=threading.Event(); self._wake=threading.Event(); self._event_queue=queue.Queue(); self._config={}; self._baseline=None; self._seen=set(); self._ack=set(); self._last_directories=set(); self._last_directory_info={}
    def configure(self,config,baseline):
        with self._lock: self._config=dict(config); self._baseline=baseline
    def replace_baseline(self,baseline):
        with self._lock: self._baseline=baseline; self._seen.clear(); self._ack.clear()
    def acknowledge(self,signature):
        with self._lock: self._ack.add(tuple(signature))
    def stop(self): self._stop.set(); self._wake.set()
    def run(self):
        observer=None; watch_issue=None
        try:
            with self._lock: initial=dict(self._config)
            target=Path(initial.get('target',''))
            if target.is_symlink(): raise OSError('The selected monitoring target is a symbolic link and will not be followed.')
            watch_root=target if target.is_dir() else target.parent
            file_target=str(target) if target.is_file() else None
            observer=Observer(); observer.schedule(_WatchQueueHandler(self._event_queue,self._wake,str(watch_root),bool(initial.get('recursive',True)),file_target),str(watch_root),recursive=bool(initial.get('recursive',True)) if not file_target else False); observer.start()
        except Exception as exc:
            watch_issue={'path':'.','error':f'Native event watcher unavailable: {type(exc).__name__}: {exc}'}
        first=True
        while not self._stop.is_set():
            with self._lock: config=dict(self._config)
            if not config.get('target'): self._wake.wait(.25); self._wake.clear(); continue
            if not first: self._wake.wait(max(0.25,float(config.get('interval',1.0))))
            first=False
            if self._stop.is_set(): break
            # The UI may save/activate the first baseline while this worker waits.
            # Read the trusted snapshot after the wait so this scan does not use a
            # stale None (or stale profile) captured at the previous loop boundary.
            with self._lock: config=dict(self._config); baseline=self._baseline
            if not config.get('target'): continue
            self._wake.clear(); started=time.perf_counter()
            try: result=scan_tree(config['target'],config['recursive'],config['max_bytes'],config['excludes'])
            except Exception as exc:
                result={'files':{},'directories':set(),'directory_info':{},'absolute_target':os.path.abspath(config['target']),'hash_stats':{'bytes':0,'sha256_seconds':0,'sha512_seconds':0},'issues':[{'path':config['target'],'error':f'Unexpected scan failure: {type(exc).__name__}: {exc}'}]}
            if watch_issue and not any('Native event watcher unavailable' in i['error'] for i in result['issues']): result['issues'].append(watch_issue)
            baseline_files=(baseline or {}).get('files',{})
            single_file_key=Path(config['target']).name if len(baseline_files)==1 and Path(config['target']).name in baseline_files else None
            for issue in result['issues']:
                try:
                    if Path(issue['path']).is_absolute(): issue['path']=single_file_key or '.'
                except (TypeError,ValueError): issue['path']='.'
            result['directories']=retain_unavailable_directories(self._last_directories,result['directories'],self._last_directory_info,result['issues'],result['directory_info'])
            self._last_directories=set(result['directories']); self._last_directory_info=dict(result['directory_info'])
            if baseline: result['files']=retain_unavailable(baseline.get('files',{}),result['files'],result['issues'])
            # A baseline loaded from disk has hashes but intentionally no file contents.
            # Cache only text observed unchanged against that trusted hash so later local
            # reports can compute exact character and line deltas without altering trust.
            if baseline:
                seeded_files=dict(baseline.get('files',{})); seeded=False
                for rel,old in seeded_files.items():
                    now=result['files'].get(rel)
                    if (now and old.get('_text') is None and now.get('_text') is not None and old.get('status')=='hashed'
                        and old.get('sha256')==now.get('sha256') and old.get('sha512')==now.get('sha512') and old.get('size')==now.get('size')):
                        seeded_files[rel]={**old,'_text':now['_text']}; seeded=True
                if seeded:
                    enriched={**baseline,'files':seeded_files}
                    with self._lock:
                        if self._baseline is baseline: self._baseline=enriched
                    baseline=enriched
            detected=detect_events(baseline,result,result['issues'],config['methods']) if baseline else []
            with self._lock:
                visible,fresh=update_alert_lifecycle(detected,self._seen,self._ack)
            observed=[]
            while True:
                try: observed.append(self._event_queue.get_nowait())
                except queue.Empty: break
            result['watch_events']=observed; result['events']=visible; result['new_events']=fresh; result['elapsed']=time.perf_counter()-started
            result['baseline_missing']=baseline is None; self.scan_ready.emit(result)
        if observer:
            try: observer.stop(); observer.join(timeout=3)
            except Exception: pass

class DonutOverview(QWidget):
    """Widget-based event/file-state summary; avoids custom-painter stalls."""
    def __init__(self,parent=None):
        super().__init__(parent); self.events=Counter(); self.files=Counter(); self.setMinimumSize(300,220)
        layout=QVBoxLayout(self); layout.setContentsMargins(2,2,2,2); layout.setSpacing(6)
        event_title=QLabel('FILE EVENTS'); event_title.setObjectName('muted'); event_title.setStyleSheet('font-size:8pt;font-weight:800'); layout.addWidget(event_title)
        self.event_rows={}
        for name in ('CREATED','TAMPERED','DELETED','RENAMED'):
            row=QHBoxLayout(); row.setSpacing(7); label=QLabel(name); label.setMinimumWidth(74); label.setStyleSheet(f'color:{EVENT_COLORS[name]};font-weight:700;font-size:8pt'); bar=QProgressBar(); bar.setRange(0,1); bar.setValue(0); bar.setTextVisible(False); bar.setFixedHeight(12); bar.setStyleSheet(f'QProgressBar{{background:{C["void"]};border:1px solid {C["line"]};border-radius:4px}} QProgressBar::chunk{{background:{EVENT_COLORS[name]};border-radius:3px}}'); count=QLabel('0'); count.setMinimumWidth(24); count.setAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter); row.addWidget(label); row.addWidget(bar,1); row.addWidget(count); layout.addLayout(row); self.event_rows[name]=(bar,count)
        file_title=QLabel('CURRENT FILE STATES'); file_title.setObjectName('muted'); file_title.setStyleSheet('font-size:8pt;font-weight:800;padding-top:4px'); layout.addWidget(file_title)
        self.file_counts={}; state_row=QHBoxLayout(); state_row.setSpacing(6)
        for name,color in (('HASHED',C['green']),('LOCKED',C['orange']),('EXCLUDED',C['muted'])):
            tile=QFrame(); tile.setObjectName('panel'); cell=QVBoxLayout(tile); cell.setContentsMargins(7,5,7,5); cell.setSpacing(2); label=QLabel(name); label.setStyleSheet(f'color:{color};font-size:7pt;font-weight:800'); value=QLabel('0'); value.setStyleSheet(f'color:{C["text"]};font:bold 14pt Consolas,monospace'); cell.addWidget(label); cell.addWidget(value); state_row.addWidget(tile,1); self.file_counts[name]=value
        layout.addLayout(state_row); layout.addStretch(1)
    def update_data(self,events,files):
        self.events=Counter(e.get('type','') for e in events)
        self.files=Counter(r.get('status','unknown').upper() for r in files.values())
        maximum=max(1,max((self.events.get(name,0) for name in self.event_rows),default=0))
        for name,(bar,count_label) in self.event_rows.items():
            count=self.events.get(name,0); bar.setRange(0,maximum); bar.setValue(count); count_label.setText(str(count))
        for name,label in self.file_counts.items(): label.setText(f'{self.files.get(name,0):,}')

class AreaTrendChart(QWidget):
    """Compact scan history with separated file-volume area and alert trend line."""
    def __init__(self,parent=None): super().__init__(parent); self.samples=[]; self.setMinimumSize(300,170)
    def add_sample(self,files,alerts):
        self.samples.append((int(files),int(alerts))); self.samples=self.samples[-36:]; self.update()
    def paintEvent(self,event):
        p=QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing); bounds=self.rect().adjusted(7,7,-7,-7); p.setPen(QPen(QColor(C['line']),1)); p.drawRoundedRect(bounds,6,6)
        p.setPen(QColor(C['text'])); p.setFont(QFont('Segoe UI',8,QFont.Weight.Bold)); p.drawText(bounds.adjusted(10,5,-5,-5),Qt.AlignmentFlag.AlignTop|Qt.AlignmentFlag.AlignLeft,'SCAN TREND  ·  FILES / ALERTS')
        plot=bounds.adjusted(34,31,-12,-22)
        p.setFont(QFont('Consolas',7)); p.setPen(QColor(C['muted']))
        for i,label in enumerate(('100%','50%','0')):
            y=plot.top()+i*plot.height()/2; p.drawLine(int(plot.left()),int(y),int(plot.right()),int(y)); p.drawText(QRectF(bounds.left()+4,y-7,27,14),Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter,label)
        if len(self.samples)<2:
            p.drawText(plot,Qt.AlignmentFlag.AlignCenter,'Trend fills in with each scan.'); return
        files=[s[0] for s in self.samples]; alerts=[s[1] for s in self.samples]; max_files=max(1,max(files)); max_alerts=max(1,max(alerts)); points=[]
        for i,value in enumerate(files): points.append((plot.left()+i*plot.width()/(len(files)-1),plot.bottom()-value/max_files*plot.height()))
        area=QPainterPath(); area.moveTo(points[0][0],plot.bottom()); area.lineTo(points[0][0],points[0][1]);
        for x,y in points[1:]: area.lineTo(x,y)
        area.lineTo(points[-1][0],plot.bottom()); area.closeSubpath(); fill=QColor(C['blue']); fill.setAlpha(65); p.fillPath(area,fill); p.setPen(QPen(QColor(C['blue']),2)); p.drawPath(area)
        alert_points=[]
        for i,value in enumerate(alerts): alert_points.append((plot.left()+i*plot.width()/(len(alerts)-1),plot.bottom()-value/max_alerts*plot.height()))
        path=QPainterPath(); path.moveTo(*alert_points[0])
        for point in alert_points[1:]: path.lineTo(*point)
        p.setPen(QPen(QColor(C['red']),2)); p.drawPath(path)
        p.setPen(QColor(C['blue'])); p.drawText(int(plot.left()),int(bounds.bottom()-4),'■ FILES')
        p.setPen(QColor(C['red'])); p.drawText(int(plot.left()+70),int(bounds.bottom()-4),'— ALERTS')
class SettingsDialog(QDialog):
    changePasswordRequested=pyqtSignal()
    def __init__(self,config,parent=None):
        super().__init__(parent); self.setWindowTitle('File Integrity Monitor · Settings'); self.setMinimumWidth(610); self.config=config
        layout=QVBoxLayout(self); title=QLabel('⚙  SETTINGS & STORAGE'); title.setObjectName('dialogTitle'); layout.addWidget(title)
        form=QFormLayout(); self.theme=QComboBox()
        for label,key in (('Deep Cyber Dark','dark'),('Corporate Cobalt','cobalt'),('Midnight Blue','midnight'),('Graphite Amber','graphite'),('Arctic Light','arctic')): self.theme.addItem(label,key)
        self.theme.setCurrentIndex(max(0,self.theme.findData(config.get('theme',ACTIVE_THEME))))
        self.hashes=QComboBox(); self.hashes.addItem('SHA-256 + SHA-512',('sha256','sha512')); self.hashes.addItem('SHA-256',('sha256',)); self.hashes.addItem('SHA-512',('sha512',));
        for i in range(self.hashes.count()):
            if self.hashes.itemData(i)==tuple(config['methods']): self.hashes.setCurrentIndex(i)
        self.recursive=QCheckBox('Include all nested subfolders'); self.recursive.setChecked(config['recursive'])
        self.maxgb=QDoubleSpinBox(); self.maxgb.setRange(0.01,1024); self.maxgb.setDecimals(2); self.maxgb.setValue(config['max_bytes']/1024**3)
        self.interval=QDoubleSpinBox(); self.interval.setRange(0.25,3600); self.interval.setDecimals(2); self.interval.setSuffix(' sec'); self.interval.setValue(config['interval'])
        self.excludes=QLineEdit(','.join(config['excludes'])); self.excludes.setPlaceholderText('.git,__pycache__,node_modules')
        self.ai_enabled=QCheckBox('Enable optional AI incident analysis'); self.ai_enabled.setChecked(config.get('llm_enabled',False))
        self.provider=QComboBox(); self.provider.addItem('Google Gemini API · free tier available','gemini'); self.provider.addItem('Local Ollama · offline','ollama'); self.provider.setCurrentIndex(max(0,self.provider.findData(config.get('llm_provider','gemini'))))
        self.model=QComboBox(); self.model.setEditable(True); self.model.addItems(['gemini-3.5-flash-lite','gemini-3.6-flash','gemini-3.8-flash','llama3.1']); self.model.setCurrentText(config.get('llm_model','gemini-3.5-flash-lite'))
        self.analysis_timeout=QDoubleSpinBox(); self.analysis_timeout.setRange(15,180); self.analysis_timeout.setDecimals(0); self.analysis_timeout.setSuffix(' sec'); self.analysis_timeout.setValue(config.get('analysis_timeout_seconds',90)); self.analysis_timeout.setToolTip('Maximum time for each Gemini API attempt. A temporary 503 retry can use a second attempt.')
        self.api_key=QLineEdit(config.get('llm_api_key') or get_saved_api_key()); self.api_key.setEchoMode(QLineEdit.EchoMode.Password); self.api_key.setPlaceholderText('Paste your Google AI Studio API key'); self.api_key.setClearButtonEnabled(True)
        self.remember_key=QCheckBox('Save key securely in this user account’s credential vault'); self.remember_key.setChecked(bool(self.api_key.text()))
        self.storage=QLineEdit(config.get('storage_dir',str(db_path().parent))); self.storage.setReadOnly(True); self.storage.setToolTip('Folder where baselines.json and baseline history are stored.')
        browse=QPushButton('Browse…'); browse.clicked.connect(self.choose_storage); storage_row=QWidget(); storage_layout=QHBoxLayout(storage_row); storage_layout.setContentsMargins(0,0,0,0); storage_layout.addWidget(self.storage,1); storage_layout.addWidget(browse)
        form.addRow('Application theme',self.theme); form.addRow('Hash methods',self.hashes); form.addRow('Scan nested folders',self.recursive); form.addRow('Skip files larger than (GB)',self.maxgb); form.addRow('Scan interval',self.interval); form.addRow('Excluded folder names',self.excludes)
        form.addRow('AI analysis',self.ai_enabled); form.addRow('AI provider',self.provider); form.addRow('Gemini model',self.model); form.addRow('Request timeout per attempt',self.analysis_timeout); form.addRow('Google API key',self.api_key); form.addRow('',self.remember_key); form.addRow('Baseline storage folder',storage_row); layout.addLayout(form)
        self.provider.currentIndexChanged.connect(self.provider_changed)
        self.provider_changed()
        link=QLabel('<a href="https://aistudio.google.com/app/apikey">Get a Google Gemini API key in AI Studio</a>'); link.setOpenExternalLinks(True); layout.addWidget(link)
        help=QLabel('Gemini’s free tier has model-specific quotas and can change. The key is saved only if you select secure saving; it uses the operating system credential vault. Incident metadata is sent to Google when Gemini analysis runs; file contents are not sent. SHA-256 and SHA-512 both detect byte changes; SHA-512 produces a longer digest.'); help.setWordWrap(True); help.setObjectName('muted'); layout.addWidget(help)
        change=QPushButton('Change baseline database password…'); change.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton)); change.clicked.connect(self.changePasswordRequested.emit); layout.addWidget(change)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Save|QDialogButtonBox.StandardButton.Cancel); buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject); layout.addWidget(buttons); self.setStyleSheet(APP_QSS)
    def choose_storage(self):
        selected=QFileDialog.getExistingDirectory(self,'Choose baseline and application data folder',self.storage.text() or str(Path.home()))
        if selected: self.storage.setText(selected)
    def provider_changed(self):
        is_gemini=self.provider.currentData()=='gemini'
        self.api_key.setEnabled(is_gemini); self.remember_key.setEnabled(is_gemini)
        self.model.setToolTip('Google AI Studio model ID.' if is_gemini else 'Ollama model installed locally, for example llama3.1.')
        current=self.model.currentText().strip()
        if is_gemini and current=='llama3.1': self.model.setCurrentText('gemini-3.5-flash-lite')
        elif not is_gemini and current.startswith('gemini-'): self.model.setCurrentText('llama3.1')
    def value(self): return {'theme':self.theme.currentData(),'methods':self.hashes.currentData(),'recursive':self.recursive.isChecked(),'max_bytes':int(self.maxgb.value()*1024**3),'interval':self.interval.value(),'excludes':[x.strip() for x in self.excludes.text().split(',') if x.strip()],'llm_enabled':self.ai_enabled.isChecked(),'llm_provider':self.provider.currentData(),'llm_model':self.model.currentText().strip(),'analysis_timeout_seconds':int(self.analysis_timeout.value()),'llm_api_key':self.api_key.text(),'remember_api_key':self.remember_key.isChecked(),'storage_dir':self.storage.text().strip()}

DEFAULT_ANALYSIS_TIMEOUT_SECONDS=90
MIN_ANALYSIS_TIMEOUT_SECONDS=15
MAX_ANALYSIS_TIMEOUT_SECONDS=180
DEFAULT_GEMINI_MODEL='gemini-3.5-flash-lite'
ANALYSIS_RETRY_LIMIT=1
ANALYSIS_MAX_OUTPUT_TOKENS=1400
LLM_RETRY={'attempts':3,'initial_delay_seconds':1.0,'maximum_delay_seconds':4.0}
ANALYSIS_RESPONSE_SCHEMA={
    'type':'OBJECT',
    'properties':{
        'technical_interpretation':{'type':'STRING'},
        'potential_impact':{'type':'STRING'},
        'priority_advisory':{'type':'STRING','enum':['INFO','LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN']},
        'hypotheses':{'type':'ARRAY','items':{'type':'STRING'}},
        'investigation_steps':{'type':'ARRAY','items':{'type':'STRING'}},
        'missing_evidence':{'type':'ARRAY','items':{'type':'STRING'}},
    },
    'required':['technical_interpretation','potential_impact','priority_advisory','hypotheses','investigation_steps','missing_evidence'],
    'propertyOrdering':['technical_interpretation','potential_impact','priority_advisory','hypotheses','investigation_steps','missing_evidence'],
}
TRANSIENT_ANALYSIS_STATUS={503}

class AnalysisCancelled(Exception): pass

def analysis_logger():
    """Write bounded, secret-free diagnostics to the per-user application data folder."""
    logger=logging.getLogger('fim.analysis')
    logger.setLevel(logging.INFO)
    logger.propagate=False
    if not logger.handlers:
        try:
            log_dir=default_data_dir()/'logs'; log_dir.mkdir(parents=True,exist_ok=True)
            handler=RotatingFileHandler(log_dir/'analysis.log',maxBytes=1_000_000,backupCount=3,encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logger.addHandler(handler)
        except OSError:
            logger.addHandler(logging.NullHandler())
    return logger

def _http_status(exc):
    for value in (getattr(exc,'status_code',None),getattr(exc,'code',None),getattr(exc,'status',None),getattr(getattr(exc,'response',None),'status_code',None),getattr(getattr(exc,'response',None),'status',None)):
        try:
            code=int(value)
            if 400<=code<=599: return code
        except (TypeError,ValueError): pass
    match=re.search(r'\b([45]\d\d)\b',str(exc))
    return int(match.group(1)) if match else None

def build_incident_context(event,related_events=()):
    """Build a small evidence-only payload from fields the monitor actually records."""
    ev=dict(event or {}); kind=str(ev.get('type') or 'UNKNOWN').upper(); diff=ev.get('diff') or {}
    statuses={
        'CREATED':('Absent from selected baseline','Present and hashed in latest scan'),
        'TAMPERED':('Present and hashed in selected baseline','Present and hashed in latest scan; selected digest differs'),
        'DELETED':('Present and hashed in selected baseline','Absent from latest successful scan'),
        'RENAMED':('Present at old relative path','Present at new relative path; hash and size match'),
    }
    before,after=statuses.get(kind,('Unknown','Unknown'))
    context={'event_type':kind,'relative_path':ev.get('path'),'baseline_status':before,'current_status':after,
        'detection_timestamp':ev.get('time'),'observed_detail':ev.get('detail'),
        'baseline_bytes':ev.get('old_size'),'current_bytes':ev.get('new_size'),
        'baseline_sha256':ev.get('old_hash'),'current_sha256':ev.get('new_hash'),
        'baseline_sha512':ev.get('old_sha512'),'current_sha512':ev.get('new_sha512'),
        'known_limitations':['The monitor does not record the process or user responsible for the change.',
            'A hash difference establishes changed bytes, not malicious intent.',
            'File contents are not included in this request.']}
    if ev.get('old_path'): context['old_relative_path']=ev['old_path']
    if ev.get('new_path'): context['new_relative_path']=ev['new_path']
    question=str(ev.get('_analyst_question') or '').strip()
    if question: context['analyst_question']=question[:1200]
    history=ev.get('_chat_history')
    if isinstance(history,list):
        context['recent_chat_context']=[{'question':str(turn.get('question',''))[:600],'answer':str(turn.get('answer',''))[:900]} for turn in history[-3:] if isinstance(turn,dict)]
    if isinstance(diff,dict) and diff:
        context['text_diff_metadata']={key:diff[key] for key in ('removed','added','old_chars','new_chars','char_delta') if key in diff}
    return {key:value for key,value in context.items() if value is not None}

def validate_analysis_response(text):
    """Reject malformed or unbounded model output before it reaches the report UI."""
    content=str(text or '').strip()
    if content.startswith('```'):
        content=re.sub(r'^```(?:json)?\s*|\s*```$','',content,flags=re.I).strip()
    try: data=json.loads(content)
    except (ValueError,TypeError) as exc: raise ValueError('The analysis service returned invalid JSON. The local evidence report is still available.') from exc
    if not isinstance(data,dict): raise ValueError('The analysis service returned an invalid report structure.')
    required=('technical_interpretation','potential_impact','priority_advisory','hypotheses','investigation_steps','missing_evidence')
    if any(key not in data for key in required): raise ValueError('The analysis service returned an incomplete report. The local evidence report is still available.')
    for key in ('technical_interpretation','potential_impact'):
        if not isinstance(data[key],str) or not data[key].strip() or len(data[key])>4000: raise ValueError('The analysis service returned invalid report text.')
    if data['priority_advisory'] not in {'INFO','LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN'}: raise ValueError('The analysis service returned an invalid advisory priority.')
    for key in ('hypotheses','investigation_steps','missing_evidence'):
        values=data[key]
        if not isinstance(values,list) or not values or len(values)>12 or any(not isinstance(x,str) or not x.strip() or len(x)>1000 for x in values):
            raise ValueError('The analysis service returned an invalid evidence list.')
    return {key:data[key] for key in required}

def local_incident_report(event,notice=None):
    """Deterministic fallback composed only from verified monitor event fields."""
    ev=event or {}; kind=str(ev.get('type') or 'UNKNOWN').upper()
    interpretation={
        'DELETED':'The file was present in the selected baseline but was absent from the latest successful scan. The scan evidence does not establish why it is missing.',
        'CREATED':'The latest scan found a readable file that was not present in the selected baseline.',
        'TAMPERED':'The file remains present, but its selected cryptographic digest differs from the baseline. This confirms a byte-level change only.',
        'RENAMED':'A removed baseline path and a new path have matching SHA-256, SHA-512, and size. This supports a rename or move match, but does not identify the actor.',
    }.get(kind,'A file-integrity event was recorded. Review the observed fields below.')
    impact={
        'DELETED':'Availability or application behavior could be affected if this file is required. Its purpose and operational impact are not known from the scan alone.',
        'CREATED':'The new file may be expected or unexpected. Its function and risk cannot be determined from presence alone.',
        'TAMPERED':'Changed bytes may affect how the file is used. The file role and legitimacy of the change are not established by its digest.',
        'RENAMED':'References to the prior path may be affected. The scan cannot determine whether the move was authorized.',
    }.get(kind,'Potential impact cannot be determined from the recorded event metadata alone.')
    missing=['The process and user responsible for the change are not recorded by this monitor.',
        'Authorization, file purpose, and related operating-system audit records were not supplied.']
    if kind=='DELETED': missing.append('No deletion process, user attribution, or reason is established by the missing-path observation.')
    return {'technical_interpretation':interpretation,'potential_impact':impact,
        'hypotheses':['The change may be an authorized administrative or application action.',
            'An unauthorized action is also possible; current evidence does not distinguish these explanations.'],
        'investigation_steps':['Confirm whether the change was expected with the file owner or change record.',
            'Compare the file with a trusted copy or version-control history when available.',
            'Review operating-system and application audit logs for the observed time and path.'],
        'missing_evidence':missing,'analysis_notice':notice or ''}

def forensic_report_html(raw,event):
    """Render verified local evidence separately from advisory model interpretation."""
    data=raw if isinstance(raw,dict) else {}; ev=event or {}; kind=str(ev.get('type') or data.get('classification') or 'FORENSIC REVIEW').upper()
    local_priority={'TAMPERED':'HIGH','DELETED':'HIGH','CREATED':'MEDIUM','RENAMED':'LOW'}.get(kind)
    priority=local_priority or str(data.get('priority') or data.get('priority_advisory') or 'INFO').upper()
    priority_color={'CRITICAL':C['red'],'HIGH':C['red'],'MEDIUM':C['orange'],'LOW':C['blue'],'INFO':C['green'],'UNKNOWN':C['muted']}.get(priority,C['orange'])
    old=ev.get('old_size'); new=ev.get('new_size'); delta=new-old if isinstance(old,int) and isinstance(new,int) else None
    table_rows=[]
    for label,value in [('Relative path',ev.get('path') or ev.get('target')),('Detected by monitor',display_timestamp(ev.get('time'))),
        ('Baseline status',{'DELETED':'Present and hashed','CREATED':'Absent','TAMPERED':'Present and hashed','RENAMED':'Present at old path'}.get(kind)),
        ('Latest scan status',{'DELETED':'Absent in latest successful scan','CREATED':'Present and hashed','TAMPERED':'Present; selected digest differs','RENAMED':'Present at new path'}.get(kind)),
        ('Size, bytes',None if old is None and new is None else f"{old if old is not None else 'unknown'} -> {new if new is not None else 'unknown'}"+(f' ({delta:+,})' if delta is not None else '')),
        ('SHA-256',None if not ev.get('old_hash') and not ev.get('new_hash') else f"{ev.get('old_hash') or 'not available'} -> {ev.get('new_hash') or 'not available'}"),
        ('SHA-512',None if not ev.get('old_sha512') and not ev.get('new_sha512') else f"{ev.get('old_sha512') or 'not available'} -> {ev.get('new_sha512') or 'not available'}")]:
        if value is not None: table_rows.append((label,str(value)))
    if 'old_path' in ev: table_rows.append(('Previous relative path',str(ev['old_path'])))
    diff=ev.get('diff') or {}
    if isinstance(diff,dict):
        for k,label in [('removed','Lines removed'),('added','Lines added'),('char_delta','Character delta')]:
            if k in diff: table_rows.append((label,str(diff[k])))
    observed=[]
    if kind=='DELETED': observed.append('The file was present in the selected baseline but was not found during the latest successful scan. The monitor excludes scan failures from deletion classification.')
    elif kind=='CREATED': observed.append('The latest scan found a readable file that was not present in the selected baseline.')
    elif kind=='TAMPERED': observed.append('The file was present in both the selected baseline and latest scan, and the configured digest comparison differed.')
    elif kind=='RENAMED': observed.append('The prior path disappeared and a new path had matching SHA-256, SHA-512, and file size.')
    if ev.get('detail'): observed.append(str(ev['detail']))
    if not observed:
        existing=data.get('evidence_footprints') or data.get('evidence') or []
        observed=list(existing) if isinstance(existing,list) else [str(existing)] if existing else []
    if not observed: observed=['No file event fields were supplied for this report.']
    technical=str(data.get('technical_interpretation') or data.get('summary') or data.get('impact') or 'A file-integrity event was recorded. Review the observed fields; the cause is not established by these fields alone.')
    potential=str(data.get('potential_impact') or data.get('impact_assessment') or 'Potential impact depends on the file purpose and its use, which this scan does not establish.')
    if data.get('analysis_error'): technical='AI analysis was unavailable: '+str(data['analysis_error'])+'. The observed evidence below remains available.'
    if data.get('analysis_notice'): technical=str(data['analysis_notice'])+' '+technical
    hypotheses=data.get('hypotheses') or []
    if isinstance(hypotheses,str): hypotheses=[hypotheses]
    if not hypotheses: hypotheses=['The reason for this event cannot be determined from the collected file metadata alone.']
    steps=data.get('investigation_steps') or data.get('containment_playbook') or data.get('containment_steps') or []
    if isinstance(steps,str): steps=[steps]
    if not steps: steps=['Confirm whether the change was authorized.','Compare with a trusted source and preserve the alert record.','Review operating-system or application audit records for the observed time and path.']
    missing=data.get('missing_evidence') or []
    if isinstance(missing,str): missing=[missing]
    missing=list(missing)
    if ev:
        missing.extend(['The process and user responsible for the change are not recorded by this monitor.','Authorization and the file purpose are not established by the hash comparison.'])
    if not missing: missing=['No additional evidence gaps were supplied. Verify the underlying records before drawing conclusions.']
    advisory=data.get('priority_advisory') if data.get('_analysis_source') in ('Gemini','Ollama') else None
    if data.get('analysis_error'): interpretation_heading='AI ANALYSIS UNAVAILABLE · LOCAL EVIDENCE RETAINED'
    elif data.get('_analysis_source')=='Gemini': interpretation_heading='GEMINI INTERPRETATION · AI-GENERATED ADVISORY'
    elif data.get('_analysis_source')=='Local rule engine': interpretation_heading='LOCAL INTERPRETATION · RULE-BASED ADVISORY'
    elif data.get('_analysis_source')=='Ollama': interpretation_heading='LOCAL OLLAMA INTERPRETATION · AI-GENERATED ADVISORY'
    else: interpretation_heading='TECHNICAL INTERPRETATION · ADVISORY'
    rows=''.join(f'<tr><th>{escape(str(k))}</th><td>{escape(str(v))}</td></tr>' for k,v in table_rows)
    def list_html(values,numbered=False):
        tag='ol' if numbered else 'ul'
        return '<'+tag+'>'+''.join(f'<li>{escape(str(x))}</li>' for x in values[:12])+'</'+tag+'>'
    observed_html=list_html(observed)
    evidence_rows=rows or '<tr><th>Evidence</th><td>No structured file metadata is available.</td></tr>'
    panel=C['panel']; border=C['line']; text_color=C['text']; muted=C['muted']; void=C['void']
    badge=f'<span class="badge">{escape(priority)} APPLICATION PRIORITY</span>'
    if advisory: badge+=f' &nbsp; <span class="muted">AI priority suggestion: {escape(str(advisory))} (advisory only)</span>'
    extra=data.get('vulnerability_breakdown') or data.get('findings') or []
    if isinstance(extra,str): extra=[extra]
    extra_html=f'<div class="card"><h2>RELATED FINDINGS (UNVERIFIED)</h2>{list_html(extra)}</div>' if extra else ''
    return f'''<!doctype html><html><head><meta charset="utf-8"><style>body{{background:{void};color:{text_color};font-family:Segoe UI,Arial,sans-serif;font-size:10pt;margin:8px}} .banner,.card{{background:{panel};border:1px solid {border};border-radius:6px;padding:10px;margin-bottom:8px}} .banner{{border-left:5px solid {priority_color}}} .banner h1{{font-size:14pt;margin:0 0 6px}} .badge{{display:inline-block;background:{priority_color};color:#fff;border-radius:4px;padding:4px 8px;font-weight:bold}} h2{{font-size:10pt;margin:0 0 6px;color:{C['accent']}}} table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:5px 6px;border-bottom:1px solid {border};vertical-align:top;overflow-wrap:anywhere}} th{{width:140px;color:{muted}}} td{{font-family:Consolas,monospace}} ul,ol{{margin:4px 0 0;padding-left:20px}} li{{padding:2px 0}} .muted{{color:{muted}}}</style></head><body><div class="banner"><h1>{escape(kind)} · FORENSIC REVIEW</h1>{badge}<p>Facts below come from the monitor. Interpretation and hypotheses are advisory; this application does not attribute a change to a person or process.</p></div><div class="card"><h2>A. OBSERVED EVIDENCE</h2><table>{evidence_rows}</table>{observed_html}</div><div class="card"><h2>B. {escape(interpretation_heading)}</h2><p>{escape(technical)}</p></div><div class="card"><h2>C. POTENTIAL SECURITY IMPACT</h2><p>{escape(potential)}</p></div><div class="card"><h2>D. CONFIRMED FACTS</h2>{list_html(observed)}</div><div class="card"><h2>E. PLAUSIBLE EXPLANATIONS (HYPOTHESES)</h2>{list_html(hypotheses)}</div><div class="card"><h2>F. RECOMMENDED INVESTIGATION STEPS</h2>{list_html(steps,True)}</div><div class="card"><h2>G. EVIDENCE STILL MISSING</h2>{list_html(missing)}</div>{extra_html}</body></html>'''
def _friendly_analysis_error(exc):
    code=_http_status(exc)
    if code==503: return 'Threat Intelligence service is temporarily under high load. Retry later; local incident details remain available.'
    if code==429: return 'The analysis service quota is currently exhausted. Check your plan or retry after the quota resets.'
    if code in (401,403): return 'The analysis service rejected the API key. Check the key in Settings.'
    if code in (408,504): return 'The analysis request timed out. The local forensic evidence is still available; retry when the service is responsive.'
    if isinstance(exc,(TimeoutError,urllib.error.URLError,ConnectionError)) or 'timeout' in type(exc).__name__.lower(): return 'The analysis request timed out. The local forensic evidence is still available; retry when the service is responsive.'
    if isinstance(exc,ValueError):
        message=str(exc)
        if message.startswith(('Enable incident analysis','Choose a model','Add a Google Gemini API key','The analysis service returned','Select Google Gemini')): return message
    return 'The analysis service could not complete this request. Verify the provider settings and try again.'

class AnalysisWorker(QThread):
    partial=pyqtSignal(str); completed=pyqtSignal(object); failed=pyqtSignal(str); cancelled=pyqtSignal(); status=pyqtSignal(str,int); metrics_ready=pyqtSignal(dict)
    def __init__(self,settings,event,related_events=()):
        super().__init__(); self.settings=dict(settings); self.event=dict(event); self.related_events=tuple(related_events); self.metrics={'preparation_ms':0,'request_started_at':None,'request_ms':0,'first_response_ms':None,'total_ms':0,'retry_count':0,'http_status':None,'error_class':None,'timeout_ms':None}
    def _gemini(self,s,instruction,context):
        self._check_cancelled()
        if not s.get('llm_api_key'): raise ValueError('Add a Google Gemini API key in Settings. Use the AI Studio link to create one.')
        from google import genai
        from google.genai import types
        prompt=instruction+'\n\nEvidence supplied by the local monitor (file contents omitted):\n'+json.dumps(context,ensure_ascii=False,separators=(',',':'))
        self.metrics['preparation_ms']=round((time.perf_counter()-self.started_at)*1000)
        logger=analysis_logger(); model=s.get('llm_model',DEFAULT_GEMINI_MODEL)
        timeout_seconds=max(MIN_ANALYSIS_TIMEOUT_SECONDS,min(MAX_ANALYSIS_TIMEOUT_SECONDS,int(s.get('analysis_timeout_seconds',DEFAULT_ANALYSIS_TIMEOUT_SECONDS))))
        timeout_ms=timeout_seconds*1000; self.metrics['timeout_ms']=timeout_ms
        logger.info('analysis request prepared provider=gemini model=%s preparation_ms=%d timeout_ms=%d payload_bytes=%d',model,self.metrics['preparation_ms'],timeout_ms,len(prompt.encode('utf-8')))
        self.status.emit('Contacting Gemini with incident metadata…',0)
        client=genai.Client(api_key=s['llm_api_key'],http_options=types.HttpOptions(timeout=timeout_ms,retry_options=types.HttpRetryOptions(attempts=1)))
        request_started=time.perf_counter(); self.metrics['request_started_at']=datetime.now().astimezone().isoformat(timespec='seconds')
        logger.info('analysis request start provider=gemini model=%s request_started_at=%s timeout_ms=%d retry_limit=%d',model,self.metrics['request_started_at'],timeout_ms,ANALYSIS_RETRY_LIMIT)
        try:
            for attempt in range(ANALYSIS_RETRY_LIMIT+1):
                self._check_cancelled()
                attempt_started=time.perf_counter()
                logger.info('analysis attempt start provider=gemini model=%s attempt=%d timeout_ms=%d',model,attempt+1,timeout_ms)
                try:
                    response=client.models.generate_content(model=model,contents=prompt,
                        config=types.GenerateContentConfig(response_mime_type='application/json',response_schema=ANALYSIS_RESPONSE_SCHEMA,max_output_tokens=ANALYSIS_MAX_OUTPUT_TOKENS,thinking_config=types.ThinkingConfig(thinking_level='LOW')))
                    self._check_cancelled()
                    attempt_ms=round((time.perf_counter()-attempt_started)*1000)
                    logger.info('analysis attempt success provider=gemini model=%s attempt=%d duration_ms=%d',model,attempt+1,attempt_ms)
                    self.status.emit('Waiting for the analysis response…',0)
                    first_response=time.perf_counter(); self.metrics['first_response_ms']=round((first_response-request_started)*1000)
                    self.status.emit('Response received; validating structured findings…',0)
                    text=getattr(response,'text',None) or ''
                    if not text.strip(): raise ValueError('The analysis service returned an empty report. The local evidence report is still available.')
                    report=validate_analysis_response(text)
                    report['_analysis_source']='Gemini'
                    self.metrics['request_ms']=round((time.perf_counter()-request_started)*1000)
                    self.status.emit('Structured response validated.',0)
                    self.completed.emit(report); return
                except Exception as exc:
                    self._check_cancelled()
                    if isinstance(exc,AnalysisCancelled): raise
                    status=_http_status(exc); self.metrics['http_status']=status
                    attempt_ms=round((time.perf_counter()-attempt_started)*1000)
                    logger.warning('analysis attempt failure provider=gemini model=%s attempt=%d duration_ms=%d timeout_ms=%d error_type=%s http_status=%s',model,attempt+1,attempt_ms,timeout_ms,type(exc).__name__,status)
                    if status in TRANSIENT_ANALYSIS_STATUS and attempt<ANALYSIS_RETRY_LIMIT:
                        self.metrics['retry_count']+=1
                        logger.warning('analysis retry provider=gemini model=%s retry_count=%d retry_limit=%d',model,self.metrics['retry_count'],ANALYSIS_RETRY_LIMIT)
                        self.status.emit('Gemini is temporarily unavailable; retrying once…',0)
                        time.sleep(0.5)
                        continue
                    if status in TRANSIENT_ANALYSIS_STATUS:
                        report=local_incident_report(self.event,'Gemini remained unavailable after one retry; local evidence-based analysis is shown.')
                        report['_analysis_source']='Local rule engine'
                        self.metrics['request_ms']=round((time.perf_counter()-request_started)*1000)
                        self.completed.emit(report); return
                    raise
        finally:
            self.metrics['request_ms']=self.metrics['request_ms'] or round((time.perf_counter()-request_started)*1000)
            try: client.close()
            except Exception: logger.debug('analysis client cleanup failed')
    def _ollama(self,s,instruction,context):
        url=(s.get('llm_endpoint') or 'http://localhost:11434/api/chat').rstrip('/')
        if not url.endswith('/api/chat'): url+='/api/chat'
        payload={'model':s.get('llm_model','llama3.1'),'stream':True,'messages':[{'role':'system','content':instruction},{'role':'user','content':json.dumps(context,ensure_ascii=False)}]}
        self.status.emit('🧠 Dispatching Threat Ingestion Model…',0); raw=json.dumps(payload).encode('utf-8'); delay=LLM_RETRY['initial_delay_seconds']
        for attempt in range(LLM_RETRY['attempts']):
            try:
                request=urllib.request.Request(url,data=raw,headers={'Content-Type':'application/json'},method='POST'); pieces=[]
                with urllib.request.urlopen(request,timeout=60) as response:
                    for line in response:
                        data=json.loads(line.decode('utf-8',errors='replace')); text=data.get('message',{}).get('content','')
                        if text: pieces.append(text)
                text=''.join(pieces)
                if not text: raise ValueError('The local analysis model returned an empty report.')
                self.status.emit('Validating structured local response…',0)
                report=validate_analysis_response(text); report['_analysis_source']='Ollama'; self.completed.emit(report); return
            except Exception as exc:
                if _http_status(exc)!=503: raise
                if attempt+1>=LLM_RETRY['attempts']:
                    self.status.emit('✍️ Rendering Mitigation Protocol…',92)
                    self.completed.emit(local_incident_report(self.event)); return
                self.status.emit(f'📡 Analysis endpoint is busy; retrying request {attempt+2}/{LLM_RETRY["attempts"]}…',45)
                time.sleep(min(delay,LLM_RETRY['maximum_delay_seconds'])); delay=min(delay*2,LLM_RETRY['maximum_delay_seconds'])
    def run(self):
        self.started_at=time.perf_counter(); self.metrics['error_class']=None
        provider=self.settings.get('llm_provider','gemini'); model=self.settings.get('llm_model',DEFAULT_GEMINI_MODEL).strip()
        try:
            s=self.settings
            if not s.get('llm_enabled'): raise ValueError('Enable incident analysis in Settings first.')
            if not model: raise ValueError('Choose a model in Settings.')
            self.status.emit('📡 Synchronizing Forensic Context…',0)
            context=build_incident_context(self.event,self.related_events)
            self.metrics['preparation_ms']=round((time.perf_counter()-self.started_at)*1000)
            self.status.emit('🔐 Preparing supplied hash evidence…',0)
            instruction=('Act as a cautious file-integrity incident analyst. Analyze only the supplied JSON evidence; it contains no file contents. '
                'Return one JSON object with string fields technical_interpretation and potential_impact, priority_advisory (one of INFO, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN), '
                'and arrays of strings named hypotheses, investigation_steps, missing_evidence. '
                'If analyst_question is supplied, answer it directly in technical_interpretation using only the selected alert evidence; do not treat prior chat answers as confirmed facts. '
                'Explain the observed event and its technical meaning. Describe potential impact conditionally. '
                'List plausible benign and malicious explanations as hypotheses when appropriate, and identify missing evidence. Give proportionate investigation steps. '
                'Do not invent a user, process, motive, attack, timestamp, hash, vulnerability, or file property. A hash mismatch alone is not evidence of malware. '
                'Do not alter the event type, timestamps, sizes, or hashes. If cause or impact cannot be determined, explicitly say so. '
                'priority_advisory is a model suggestion only; the application calculates and displays its own deterministic priority.')
            if provider=='gemini': self._gemini(s,instruction,context)
            elif provider=='ollama': self._ollama(s,instruction,context)
            else: raise ValueError('Select Google Gemini or local Ollama in Settings.')
        except AnalysisCancelled:
            self.metrics['error_class']='AnalysisCancelled'
            self.cancelled.emit()
        except Exception as exc:
            self.metrics['error_class']=type(exc).__name__; self.metrics['http_status']=_http_status(exc)
            self.failed.emit(_friendly_analysis_error(exc))
        finally:
            self.metrics['total_ms']=round((time.perf_counter()-self.started_at)*1000)
            analysis_logger().info('analysis finished provider=%s model=%s preparation_ms=%d request_started_at=%s request_ms=%d first_response_ms=%s total_ms=%d timeout_ms=%s retry_count=%d http_status=%s error_type=%s',
                provider,model,self.metrics['preparation_ms'],self.metrics['request_started_at'],self.metrics['request_ms'],self.metrics['first_response_ms'],self.metrics['total_ms'],self.metrics['timeout_ms'],self.metrics['retry_count'],self.metrics['http_status'],self.metrics['error_class'])
            self.metrics_ready.emit(dict(self.metrics))

    def _check_cancelled(self):
        if self.isInterruptionRequested(): raise AnalysisCancelled()

class BaselineAuditWorker(QThread):
    completed=pyqtSignal(object)
    def __init__(self,profile): super().__init__(); self.profile=dict(profile)
    def run(self):
        p=self.profile
        try:
            result=scan_tree(p['target'],bool(p.get('recursive',True)),int(p.get('max_bytes',1024**3)),p.get('excludes',DEFAULT_EXCLUDES.split(',')))
            events=detect_events(p,result,result['issues'],p.get('methods',['sha256','sha512']))
            self.completed.emit({'profile':p,'scan':result,'events':events})
        except Exception as exc: self.completed.emit({'profile':p,'scan':None,'events':[],'error':f'{type(exc).__name__}: {exc}'})

class MainWindow(QMainWindow):
    def __init__(self,state,password,database_path=None,preferences=None):
        super().__init__(); self.state=state; self.password=password; self.worker=None; self.current={}; self.inventory_scan_valid=False; self.events=[]; self.current_visible=[]; self.alert_keys=set(); self.active_profile=None; self.alert_tree_items=[]; self.active_scans_run=0; self.total_compromises=0
        self.database_path=Path(database_path or db_path()); self.preferences=dict(preferences or load_preferences()); saved_settings=self.preferences.get('monitoring',{}); self.settings=dict(saved_settings) if isinstance(saved_settings,dict) else {}
        self.settings.setdefault('methods',('sha256','sha512')); self.settings.setdefault('recursive',True); self.settings.setdefault('max_bytes',1024**3); self.settings.setdefault('interval',1.0); self.settings.setdefault('excludes',DEFAULT_EXCLUDES.split(',')); self.settings.setdefault('llm_provider','gemini'); self.settings.setdefault('llm_model',DEFAULT_GEMINI_MODEL); self.settings.setdefault('analysis_timeout_seconds',DEFAULT_ANALYSIS_TIMEOUT_SECONDS); self.settings.setdefault('llm_enabled',False)
        self.settings['llm_api_key']=get_saved_api_key()
        self.analysis_worker=None; self.analysis_event=None; self.analysis_results={}; self.ai_chat_history={}; self.chat_pending_question=None; self.selected_event=None; self.ai_buffer=''; self.last_hash_stats={}; self.last_issues=[]; self.last_dirs=set(); self.dir_info={}; self.audit_worker=None
        self.setWindowTitle('File Integrity Monitor · Command Center'); self.setWindowIcon(app_icon()); self.resize(1500,900); self.setMinimumSize(1000,680)
        root=QWidget(); self.setCentralWidget(root); shell=QHBoxLayout(root); shell.setContentsMargins(10,10,10,10); shell.setSpacing(12)
        sidebar=QFrame(); sidebar.setObjectName('sidebar'); sidebar.setFixedWidth(235); nav_layout=QVBoxLayout(sidebar); nav_layout.setContentsMargins(12,14,12,12); nav_layout.setSpacing(7)
        brand=QLabel('◈  SentinelFIM'); self.brand_label=brand; brand.setStyleSheet(f'font-size:17pt;font-weight:800;color:{C["accent"]};padding:8px 6px'); nav_layout.addWidget(brand)
        brand_caption=QLabel('FILE INTEGRITY OPERATIONS'); brand_caption.setObjectName('muted'); brand_caption.setStyleSheet('font-size:7pt;font-weight:800;letter-spacing:1px;padding:0 7px 8px'); nav_layout.addWidget(brand_caption)
        self.pages={}; self.nav_buttons={}; self.alert_nav_badge=None
        integrity_card=QFrame(); integrity_card.setObjectName('panel'); integrity_card.setStyleSheet(f'QFrame#panel{{background:{C["input"]};border:1px solid {C["line"]};border-radius:8px}}')
        integrity_layout=QVBoxLayout(integrity_card); integrity_layout.setContentsMargins(12,10,12,10); integrity_layout.setSpacing(5)
        integrity_heading=QHBoxLayout(); shield=QLabel('◈'); shield.setStyleSheet(f'color:{C["accent"]};font-size:14pt;font-weight:800'); integrity_heading.addWidget(shield); integrity_heading.addWidget(QLabel('System Integrity')); integrity_heading.addStretch(1); integrity_layout.addLayout(integrity_heading)
        integrity_value_row=QHBoxLayout(); self.integrity_health_dot=QLabel('●'); self.integrity_health_dot.setStyleSheet(f'color:{C["muted"]}'); integrity_value_row.addWidget(self.integrity_health_dot); self.integrity_card_value=QLabel('Not assessed'); self.integrity_card_value.setStyleSheet('font-weight:800'); integrity_value_row.addWidget(self.integrity_card_value); integrity_value_row.addStretch(1); integrity_layout.addLayout(integrity_value_row)
        integrity_caption=QLabel('Baseline match rate · not a security guarantee'); integrity_caption.setObjectName('muted'); integrity_caption.setWordWrap(True); integrity_caption.setStyleSheet('font-size:8pt'); integrity_layout.addWidget(integrity_caption); nav_layout.addWidget(integrity_card)
        nav_caption=QLabel('CORE MODULES'); nav_caption.setObjectName('muted'); nav_caption.setStyleSheet('font-size:8pt;font-weight:800;letter-spacing:0.7px;padding:10px 8px 3px'); nav_layout.addWidget(nav_caption)
        nav_items=(('Dashboard',QStyle.StandardPixmap.SP_DesktopIcon),('Baseline Manager',QStyle.StandardPixmap.SP_DriveHDIcon),('Alerts',QStyle.StandardPixmap.SP_MessageBoxWarning),('System Inventory',QStyle.StandardPixmap.SP_DirOpenIcon))
        for page_name,icon in nav_items:
            button=QPushButton(page_name); button.setIcon(self.style().standardIcon(icon)); button.setObjectName('navButton'); button.setCheckable(True); button.setMinimumHeight(42); self.nav_buttons[page_name]=button
            if page_name=='Alerts':
                row=QWidget(); row_layout=QHBoxLayout(row); row_layout.setContentsMargins(0,0,5,0); row_layout.setSpacing(4); row_layout.addWidget(button,1)
                self.alert_nav_badge=QLabel(''); self.alert_nav_badge.setObjectName('alertBadge'); self.alert_nav_badge.setAlignment(Qt.AlignmentFlag.AlignCenter); self.alert_nav_badge.setFixedSize(20,20); self.alert_nav_badge.hide(); row_layout.addWidget(self.alert_nav_badge); nav_layout.addWidget(row)
            else: nav_layout.addWidget(button)
        intelligence_caption=QLabel('INTELLIGENCE & ANALYSIS'); intelligence_caption.setObjectName('muted'); intelligence_caption.setStyleSheet('font-size:7pt;font-weight:800;letter-spacing:0.5px;padding:14px 8px 3px'); nav_layout.addWidget(intelligence_caption)
        button=QPushButton('AI Assistant'); button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation)); button.setObjectName('navButton'); button.setCheckable(True); button.setMinimumHeight(42); self.nav_buttons['AI Assistant']=button; nav_layout.addWidget(button)
        button=QPushButton('Forensic Analysis'); button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogInfoView)); button.setObjectName('navButton'); button.setCheckable(True); button.setMinimumHeight(42); self.nav_buttons['Forensic Analysis']=button; nav_layout.addWidget(button)
        nav_layout.addStretch(1); nav_help=QLabel('BASELINE  ·  SCAN  ·  REVIEW'); nav_help.setObjectName('muted'); nav_help.setStyleSheet('font-size:7pt;font-weight:700;letter-spacing:0.5px;padding:8px'); nav_layout.addWidget(nav_help)
        content=QWidget(); content_layout=QVBoxLayout(content); content_layout.setContentsMargins(0,0,0,0); content_layout.setSpacing(10)
        header=QHBoxLayout(); title=QLabel('FILE INTEGRITY MONITOR'); title.setObjectName('title'); header.addWidget(title); header.addStretch(); self.status=QLabel('●  MONITORING PAUSED'); self.status.setStyleSheet(f"color:{C['orange']};font-weight:700;padding:6px 10px;border:1px solid {C['orange']};border-radius:6px"); header.addWidget(self.status); self.settings_btn=QPushButton('Settings'); self.settings_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView)); header.addWidget(self.settings_btn); content_layout.addLayout(header)
        self.page_stack=QStackedWidget(); content_layout.addWidget(self.page_stack,1); shell.addWidget(sidebar); shell.addWidget(content,1)
        dashboard_page=QWidget(); outer=QVBoxLayout(dashboard_page); outer.setContentsMargins(0,0,0,0); outer.setSpacing(10)
        dashboard_heading=QHBoxLayout(); dashboard_heading.setSpacing(8); dashboard_heading.addStretch(1); self.dashboard_start_btn=QPushButton('▶  Start monitoring'); self.dashboard_start_btn.setObjectName('primary'); self.dashboard_start_btn.setMinimumHeight(42); self.dashboard_start_btn.setMinimumWidth(180); self.dashboard_start_btn.setToolTip('Start the scheduled integrity scan for the selected target.'); self.dashboard_stop_btn=QPushButton('■  Stop monitoring'); self.dashboard_stop_btn.setObjectName('danger'); self.dashboard_stop_btn.setMinimumHeight(42); self.dashboard_stop_btn.setMinimumWidth(170); self.dashboard_stop_btn.setEnabled(False); self.analytics_button=QPushButton('▥  Scan analytics'); self.analytics_button.setMinimumHeight(42); self.analytics_button.setMinimumWidth(170); self.analytics_button.setToolTip('Open scan charts, hash throughput, and recent scan metrics.'); dashboard_heading.addWidget(self.dashboard_start_btn); dashboard_heading.addWidget(self.dashboard_stop_btn); dashboard_heading.addWidget(self.analytics_button); outer.addLayout(dashboard_heading)
        self.monitoring_page=QWidget(); monitor_layout=QVBoxLayout(self.monitoring_page); monitor_layout.setContentsMargins(0,0,0,0); monitor_layout.setSpacing(10)
        bar=QFrame(); bar.setObjectName('panel'); bh=QHBoxLayout(bar); self.target=QLineEdit(); self.target.setPlaceholderText('Paste a file or folder path · or browse your computer'); self.target.setStyleSheet(f'font-family:Consolas,monospace;background:{C["void"]};color:{C["text"]};border:1px solid {C["line"]};padding:7px'); bh.addWidget(QLabel('PROTECTED PATH')); bh.addWidget(self.target,1)
        self.file_btn=QPushButton('Choose file'); self.file_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)); self.folder_btn=QPushButton('Choose folder'); self.folder_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)); self.profile=QComboBox(); self.refresh_profiles(); bh.addWidget(self.file_btn); bh.addWidget(self.folder_btn); bh.addWidget(QLabel('Baseline')); bh.addWidget(self.profile)
        actions=QHBoxLayout(); actions.setSpacing(8); self.start_btn=QPushButton('Start monitoring'); self.start_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)); self.start_btn.setObjectName('primary'); self.stop_btn=QPushButton('Stop'); self.stop_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop)); self.stop_btn.setObjectName('danger'); self.stop_btn.setEnabled(False); self.commit_btn=QPushButton('Save baseline'); self.commit_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)); self.ack_btn=QPushButton('Acknowledge alert'); self.clear_btn=QPushButton('Clear alert log')
        self.start_btn.setToolTip('Begin periodic file hashing against the selected trusted baseline.'); self.stop_btn.setToolTip('Pause the background audit stream.'); self.commit_btn.setToolTip('Save the current clean inventory as a new trusted baseline profile.'); self.ack_btn.setToolTip('Acknowledge the selected alert without changing the trusted baseline.'); self.settings_btn.setToolTip('Configure hashing, exclusions, file size limits, and scan rate.')
        for b in (self.start_btn,self.stop_btn,self.commit_btn): actions.addWidget(b)
        actions.addStretch(1)
        summary_row=QHBoxLayout(); summary_row.setSpacing(10); self.dashboard_summary={}
        summary_icons={'scope':QStyle.StandardPixmap.SP_DirIcon,'baseline':QStyle.StandardPixmap.SP_DriveHDIcon,'integrity':QStyle.StandardPixmap.SP_DialogApplyButton,'last_scan':QStyle.StandardPixmap.SP_BrowserReload}
        for key,title_text in (('scope','FILES · FOLDERS · HASHES'),('baseline','TRUSTED BASELINE'),('integrity','INTEGRITY CHECK'),('last_scan','LAST SCAN')):
            tile=QFrame(); tile.setObjectName('panel'); tile_layout=QVBoxLayout(tile); tile_layout.setContentsMargins(16,14,16,14); tile_layout.setSpacing(8); caption_row=QHBoxLayout(); caption=QLabel(title_text); caption.setObjectName('muted'); caption.setStyleSheet('font-size:8pt;font-weight:800;letter-spacing:0.6px'); icon=QLabel(); icon.setPixmap(self.style().standardIcon(summary_icons[key]).pixmap(17,17)); caption_row.addWidget(caption); caption_row.addStretch(1); caption_row.addWidget(icon); value=QLabel('Choose a target to begin'); value.setWordWrap(True); value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse); value.setStyleSheet('font-size:14pt;font-weight:700'); detail=QLabel(''); detail.setObjectName('muted'); detail.setWordWrap(True); tile_layout.addLayout(caption_row); tile_layout.addWidget(value); tile_layout.addWidget(detail); tile_layout.addStretch(1); summary_row.addWidget(tile,1); self.dashboard_summary[key]=(value,detail)
        outer.addLayout(summary_row)
        dashboard_body=QHBoxLayout(); dashboard_body.setSpacing(10)
        distribution_panel=QFrame(); distribution_panel.setObjectName('panel'); distribution_layout=QVBoxLayout(distribution_panel); distribution_layout.setContentsMargins(16,14,16,14); distribution_layout.setSpacing(8); distribution_title=QLabel('FILE CHANGE SUMMARY'); distribution_title.setObjectName('panelTitle'); distribution_layout.addWidget(distribution_title); self.donut=DonutOverview(); self.donut.setMinimumSize(320,240); distribution_layout.addWidget(self.donut,1); dashboard_body.addWidget(distribution_panel,1)
        detail_column=QVBoxLayout(); detail_column.setSpacing(10)
        diagnostic_panel=QFrame(); diagnostic_panel.setObjectName('panel'); diagnostic_layout=QVBoxLayout(diagnostic_panel); diagnostic_layout.setContentsMargins(14,12,14,12); diagnostic_layout.setSpacing(8); diagnostic_title=QLabel('ACTIVITY & SCAN REVIEW'); diagnostic_title.setObjectName('panelTitle'); diagnostic_layout.addWidget(diagnostic_title); self.dashboard_detail_tabs=QTabWidget(); self.dashboard_activity=QListWidget(); self.dashboard_activity.setSpacing(2); self.dashboard_activity.setMinimumHeight(180); self.dashboard_activity.itemDoubleClicked.connect(lambda _item:self.navigate('Alerts')); self.dashboard_detail_tabs.addTab(self.dashboard_activity,'Recent activity'); self.dashboard_diagnostics=QTextBrowser(); self.dashboard_diagnostics.setOpenExternalLinks(False); self.dashboard_diagnostics.setMinimumSize(0,0); self.dashboard_diagnostics.setPlaceholderText('Start monitoring to see scan coverage and access diagnostics.'); self.dashboard_detail_tabs.addTab(self.dashboard_diagnostics,'Scan diagnostics'); self.dashboard_config=QTextBrowser(); self.dashboard_config.setOpenExternalLinks(False); self.dashboard_config.setMinimumSize(0,0); self.dashboard_detail_tabs.addTab(self.dashboard_config,'Protection configuration'); diagnostic_layout.addWidget(self.dashboard_detail_tabs,1); detail_column.addWidget(diagnostic_panel,1); dashboard_body.addLayout(detail_column,2); outer.addLayout(dashboard_body,1)
        self.cards=[]; metrics=QHBoxLayout()
        for label in ('MONITORED FILES','TOTAL HASH VOLUMES','DATA THROUGHPUT','ACTIVE ALERTS','SHA-256 PIPELINE','SHA-512 PIPELINE'):
            panel=QFrame(); panel.setObjectName('panel'); lay=QVBoxLayout(panel); lay.setContentsMargins(6,4,6,4); lay.setSpacing(1); small=QLabel(label); small.setObjectName('muted'); value=QLabel('—'); value.setStyleSheet('font-size:18pt;font-weight:700'); lay.addWidget(small); lay.addWidget(value); metrics.addWidget(panel,1); self.cards.append(value)
        monitor_layout.addLayout(metrics)
        chart_panel=QFrame(); chart_panel.setObjectName('panel'); chart_layout=QVBoxLayout(chart_panel); chart_layout.setContentsMargins(6,5,6,6); chart_layout.setSpacing(5); chart_title=QLabel('THREAT OVERVIEW  /  FILE INTEGRITY TELEMETRY'); chart_title.setObjectName('panelTitle'); chart_layout.addWidget(chart_title)
        kpi_row=QHBoxLayout(); kpi_row.setSpacing(8); self.telemetry_kpis={}
        for key,label,color in (('hashed','TOTAL HASHED FILES',C['green']),('scans','ACTIVE SCANS RUN',C['blue']),('compromises','INTERCEPTED COMPROMISES',C['red'])):
            tile=QFrame(); tile.setObjectName('panel'); tile.setMinimumHeight(54); tile_layout=QHBoxLayout(tile); tile_layout.setContentsMargins(12,6,12,6); caption=QLabel(label); caption.setObjectName('muted'); number=QLabel('0'); number.setStyleSheet(f'color:{color};font:bold 16pt Consolas,monospace'); tile_layout.addWidget(caption); tile_layout.addStretch(1); tile_layout.addWidget(number); kpi_row.addWidget(tile,1); self.telemetry_kpis[key]=number
        chart_layout.addLayout(kpi_row); overview_row=QHBoxLayout(); overview_row.setSpacing(5)
        trend_panel=QFrame(); trend_panel.setObjectName('panel'); trend_layout=QVBoxLayout(trend_panel); trend_layout.setContentsMargins(5,3,5,4); trend_layout.setSpacing(2); trend_label=QLabel('CONTINUOUS SCAN TREND'); trend_label.setObjectName('muted'); trend_layout.addWidget(trend_label); self.area_chart=AreaTrendChart(); trend_layout.addWidget(self.area_chart); overview_row.addWidget(trend_panel,2)
        matrix_panel=QFrame(); matrix_panel.setObjectName('panel'); matrix_layout=QVBoxLayout(matrix_panel); matrix_layout.setContentsMargins(5,3,5,4); matrix_label=QLabel('ASSET / EVENT MATRICES'); matrix_label.setObjectName('muted'); matrix_layout.addWidget(matrix_label); self.overview_tabs=QTabWidget(); self.top_assets=QTableWidget(0,3); self.top_assets.setHorizontalHeaderLabels(['Largest assets','Bytes','State']); self.recent_matrix=QTableWidget(0,3); self.recent_matrix.setHorizontalHeaderLabels(['Time','Class','Asset']);
        for table in (self.top_assets,self.recent_matrix):
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); table.verticalHeader().hide(); table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch); table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.ResizeToContents); table.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeMode.ResizeToContents); table.verticalHeader().setDefaultSectionSize(22)
        self.overview_tabs.addTab(self.top_assets,'Largest files'); self.overview_tabs.addTab(self.recent_matrix,'Recent events'); matrix_layout.addWidget(self.overview_tabs); matrix_panel.setMinimumWidth(360); matrix_panel.setMaximumWidth(500); overview_row.addWidget(matrix_panel,1); chart_layout.addLayout(overview_row); monitor_layout.addWidget(chart_panel); monitor_layout.addStretch(1)
        # Keep operational scan analytics on the dashboard without a separate nav destination.
        self.dashboard_views=QTabWidget(); self.dashboard_views.addTab(dashboard_page,'Overview'); self.dashboard_views.addTab(self.monitoring_page,'Scan analytics'); self.dashboard_views.tabBar().hide(); self.analytics_button.clicked.connect(lambda:self.dashboard_views.setCurrentIndex(1)); self.analytics_return=QPushButton('←  Dashboard'); self.analytics_return.clicked.connect(lambda:self.dashboard_views.setCurrentIndex(0)); analytics_return_row=QHBoxLayout(); analytics_return_row.addStretch(1); analytics_return_row.addWidget(self.analytics_return); monitor_layout.insertLayout(0,analytics_return_row); self.pages['Dashboard']=self.dashboard_views; self.page_stack.addWidget(self.dashboard_views)
        # Baseline registry stays focused; alert history is available in Alerts.
        history_panel=QFrame(); history_panel.setObjectName('panel'); hl=QVBoxLayout(history_panel); hl.setContentsMargins(12,12,12,12); hl.setSpacing(10); ht=QLabel('▣  BASELINE HISTORY REGISTRY'); ht.setObjectName('panelTitle'); hl.addWidget(ht); self.history_table=QTableWidget(0,6); self.history_table.setAlternatingRowColors(True); self.history_table.setTextElideMode(Qt.TextElideMode.ElideMiddle); self.history_table.verticalHeader().setDefaultSectionSize(46); self.history_table.setFont(QFont('Segoe UI',10)); self.history_table.setHorizontalHeaderLabels(['Baseline','Files','Stored size','Created','Target','Operations']); self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows); self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); hh=self.history_table.horizontalHeader(); hh.setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch); hh.setSectionResizeMode(1,QHeaderView.ResizeMode.ResizeToContents); hh.setSectionResizeMode(2,QHeaderView.ResizeMode.ResizeToContents); hh.setSectionResizeMode(3,QHeaderView.ResizeMode.ResizeToContents); hh.setSectionResizeMode(4,QHeaderView.ResizeMode.Stretch); hh.setSectionResizeMode(5,QHeaderView.ResizeMode.ResizeToContents); self.history_table.setColumnWidth(0,300); self.history_table.setColumnWidth(5,185); hl.addWidget(self.history_table)
        self.baselines_page=QWidget(); baseline_layout=QVBoxLayout(self.baselines_page); baseline_layout.setContentsMargins(8,8,8,8); baseline_layout.setSpacing(9)
        target_panel=QFrame(); target_panel.setObjectName('panel'); target_layout=QVBoxLayout(target_panel); target_layout.setContentsMargins(14,12,14,12); target_layout.setSpacing(8); target_title=QLabel('PROTECTED TARGET & MONITORING'); target_title.setObjectName('panelTitle'); target_layout.addWidget(target_title); target_layout.addWidget(bar); target_layout.addLayout(actions)
        self.baseline_summary=QLabel('Select a file or folder, then start monitoring to create or verify a baseline.'); self.baseline_summary.setObjectName('muted'); self.baseline_summary.setWordWrap(True); self.baseline_summary.setStyleSheet(f'background:{C["input"]};border:1px solid {C["line"]};border-radius:6px;padding:8px 10px'); target_layout.addWidget(self.baseline_summary); baseline_layout.addWidget(target_panel)
        baseline_heading=QHBoxLayout(); baseline_label=QLabel('SAVED BASELINES'); baseline_label.setObjectName('panelTitle'); baseline_heading.addWidget(baseline_label); baseline_heading.addStretch(1); baseline_layout.addLayout(baseline_heading); baseline_layout.addWidget(history_panel,1); self.pages['Baseline Manager']=self.baselines_page; self.page_stack.addWidget(self.baselines_page)
        self.inventory_window=QDialog(self,Qt.WindowType.Widget); self.inventory_window.setWindowTitle('FIM · Filesystem inventory'); self.inventory_window.setWindowIcon(app_icon()); self.inventory_window.setMinimumSize(0,0); itl=QVBoxLayout(self.inventory_window); itl.setContentsMargins(18,16,18,16); itl.setSpacing(12); inventory_heading=QLabel('▤  SYSTEM INVENTORY  /  BASELINE STATUS'); inventory_heading.setObjectName('dialogTitle'); itl.addWidget(inventory_heading); filter_row=QHBoxLayout(); inventory_hint=QLabel('Status is compared with the selected saved baseline. Scan errors are never counted as deletions.'); inventory_hint.setObjectName('muted'); inventory_hint.setWordWrap(True); filter_row.addWidget(inventory_hint,1); self.inventory_filter=QComboBox(); self.inventory_filter.setMinimumWidth(170); self.inventory_filter.addItem('All files','ALL'); self.inventory_filter.addItem('Tampered','TAMPERED'); self.inventory_filter.addItem('Deleted','DELETED'); self.inventory_filter.addItem('Created','CREATED'); self.inventory_filter.addItem('Unchanged','UNCHANGED'); self.inventory_filter.addItem('Scan errors','SCAN ERROR'); filter_row.addWidget(self.inventory_filter); itl.addLayout(filter_row); self.tree=QTreeWidget(); self.tree.setHeaderLabels(['File name','Relative path','Bytes','SHA-256','Integrity status']); self.tree.setAlternatingRowColors(True); self.tree.setUniformRowHeights(True); self.tree.setStyleSheet('QTreeWidget::item{padding:7px 8px;}'); self.tree.setColumnWidth(0,250); self.tree.setColumnWidth(1,380); self.tree.setColumnWidth(2,105); self.tree.setColumnWidth(3,340); self.tree.setColumnWidth(4,150); itl.addWidget(self.tree,1); self.pages['System Inventory']=self.inventory_window; self.page_stack.addWidget(self.inventory_window)
        self.forensic_window=QDialog(self,Qt.WindowType.Widget); self.forensic_window.setWindowTitle('FIM · Forensic review'); fl=QVBoxLayout(self.forensic_window); fl.setContentsMargins(18,16,18,16); self.node_tabs=QTabWidget(); self.inspector=QPlainTextEdit(); self.inspector.setReadOnly(True); self.inspector.setPlaceholderText('Select a file or directory in the Inventory page.'); self.inspector.setFont(QFont('Consolas',9)); self.node_tabs.addTab(self.inspector,'Node details'); self.report=QTextBrowser(); self.report.setOpenExternalLinks(False); self.report.setPlaceholderText('Choose an incident to inspect, then view its evidence report.'); self.node_tabs.addTab(self.report,'Forensic review'); fl.addWidget(self.node_tabs,1); self.analysis_status=QLabel(''); self.analysis_status.setObjectName('analysisStatus'); self.analysis_status.setWordWrap(True); self.analysis_status.hide(); fl.addWidget(self.analysis_status); self.analysis_progress=QProgressBar(); self.analysis_progress.setRange(0,100); self.analysis_progress.setValue(0); self.analysis_progress.setTextVisible(False); self.analysis_progress.hide(); fl.addWidget(self.analysis_progress); analysis_buttons=QHBoxLayout(); self.analyze_btn=QPushButton('Analyze selected incident with Gemini'); self.analyze_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogInfoView)); self.analyze_btn.setObjectName('primary'); self.analyze_btn.setToolTip('Sends incident metadata only. No file contents are uploaded.'); self.cancel_analysis_btn=QPushButton('Cancel analysis'); self.cancel_analysis_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop)); self.cancel_analysis_btn.setEnabled(False); analysis_buttons.addWidget(self.analyze_btn); analysis_buttons.addWidget(self.cancel_analysis_btn); fl.addLayout(analysis_buttons); self.pages['Forensic Analysis']=self.forensic_window; self.page_stack.addWidget(self.forensic_window)
        self.alert_window=QDialog(self,Qt.WindowType.Widget)
        self.alert_window.setWindowTitle('FIM · Alert Center'); self.alert_window.setWindowIcon(app_icon())
        self.alert_window.setMinimumSize(0,0)
        al=QVBoxLayout(self.alert_window); al.setContentsMargins(12,10,12,12); al.setSpacing(8)
        alert_toolbar=QHBoxLayout(); ah=QLabel('LIVE ALERT CENTER'); ah.setObjectName('dialogTitle'); ah.setFixedHeight(34); ah.setAlignment(Qt.AlignmentFlag.AlignVCenter); alert_toolbar.addWidget(ah); alert_toolbar.addStretch(1); alert_toolbar.addWidget(self.ack_btn); alert_toolbar.addWidget(self.clear_btn); al.addLayout(alert_toolbar)
        alert_feed_panel=QFrame(); alert_feed_panel.setObjectName('panel'); feed_layout=QVBoxLayout(alert_feed_panel); feed_layout.setContentsMargins(10,8,10,10); feed_layout.setSpacing(6)
        feed_title=QLabel('ACTIVE FILE ALERTS'); feed_title.setObjectName('panelTitle'); feed_layout.addWidget(feed_title)
        self.alert_list=QListWidget(); self.alert_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection); self.alert_list.setSpacing(7); feed_layout.addWidget(self.alert_list,1)
        # Keep legacy list attributes as aliases so existing selection workflows continue to work.
        self.missing_list=self.alert_list; self.change_list=self.alert_list; self.ledger=self.alert_list
        al.addWidget(alert_feed_panel,1)
        self.pages['Alerts']=self.alert_window; self.page_stack.addWidget(self.alert_window)
        self.ai_chat_page=QWidget(); chat_layout=QVBoxLayout(self.ai_chat_page); chat_layout.setContentsMargins(18,16,18,16); chat_layout.setSpacing(12)
        chat_title=QLabel('✦  AI ALERT ASSISTANT'); chat_title.setObjectName('dialogTitle'); chat_layout.addWidget(chat_title)
        chat_hint=QLabel('Choose an alert and ask a question. Gemini receives that alert’s recorded metadata and your question; file contents are not uploaded. Answers are advisory, not proof of intent or attribution.'); chat_hint.setObjectName('muted'); chat_hint.setWordWrap(True); chat_layout.addWidget(chat_hint)
        chat_row=QHBoxLayout(); chat_row.addWidget(QLabel('Selected alert')); self.chat_alert_select=QComboBox(); self.chat_alert_select.setMinimumWidth(360); chat_row.addWidget(self.chat_alert_select,1); self.chat_new_btn=QPushButton('New conversation'); self.chat_new_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder)); chat_row.addWidget(self.chat_new_btn); chat_layout.addLayout(chat_row)
        self.chat_transcript=QTextBrowser(); self.chat_transcript.setOpenExternalLinks(False); self.chat_transcript.setPlaceholderText('Select an alert, then ask about the observed change, evidence, impact, or next steps.'); chat_layout.addWidget(self.chat_transcript,1)
        ask_row=QHBoxLayout(); self.chat_input=QLineEdit(); self.chat_input.setPlaceholderText('Ask about this alert…'); self.chat_send_btn=QPushButton('Ask Gemini'); self.chat_send_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation)); self.chat_send_btn.setObjectName('primary'); ask_row.addWidget(self.chat_input,1); ask_row.addWidget(self.chat_send_btn); chat_layout.addLayout(ask_row)
        self.pages['AI Assistant']=self.ai_chat_page; self.page_stack.addWidget(self.ai_chat_page)
        mono=QFont('Consolas',10); self.tree.setFont(mono); self.ledger.setFont(mono); self.alert_list.setFont(mono)
        self.setStatusBar(QStatusBar()); self.statusBar().showMessage('Choose a target and start the audit stream. The initial clean scan becomes the immutable trusted baseline.')
        self.file_btn.clicked.connect(self.pick_file); self.folder_btn.clicked.connect(self.pick_folder); self.target.textChanged.connect(lambda _text:self._refresh_dashboard_summary()); self.start_btn.clicked.connect(self.start_monitoring); self.dashboard_start_btn.clicked.connect(self.start_monitoring); self.stop_btn.clicked.connect(self.stop_monitoring); self.dashboard_stop_btn.clicked.connect(self.stop_monitoring); self.commit_btn.clicked.connect(self.commit_baseline); self.ack_btn.clicked.connect(self.acknowledge); self.clear_btn.clicked.connect(self.clear_ledger); self.settings_btn.clicked.connect(self.open_settings); self.profile.currentIndexChanged.connect(self.change_profile); self.tree.currentItemChanged.connect(self.select_inventory); self.tree.itemDoubleClicked.connect(self.inspect_node); self.inventory_filter.currentIndexChanged.connect(self._filter_inventory); self.alert_list.currentItemChanged.connect(self.select_alert_item); self.analyze_btn.clicked.connect(self.analyze_selected); self.cancel_analysis_btn.clicked.connect(self.cancel_analysis); self.chat_send_btn.clicked.connect(self.ask_ai_about_alert); self.chat_input.returnPressed.connect(self.ask_ai_about_alert); self.chat_new_btn.clicked.connect(self.clear_ai_chat); self.chat_alert_select.currentIndexChanged.connect(self._chat_alert_changed); self.history_table.cellDoubleClicked.connect(lambda row,col:self.audit_selected_baseline())
        for name,button in self.nav_buttons.items(): button.clicked.connect(lambda checked=False,page=name:self.navigate(page))
        self.initial_baseline_targets=set()
        self.navigate('Dashboard')
        selected=self.active_baseline()
        if selected:
            self.target.setText(selected['target'])
        self.refresh_history()
        self.setStyleSheet(APP_QSS)
        self._refresh_dashboard_summary()
        self._show_welcome()
    def switch_theme(self,name):
        if name not in THEMES: return
        set_theme(name); app=QApplication.instance()
        if app: app.setStyleSheet(APP_QSS)
        # Clear per-widget dark-mode overrides so every floating window inherits
        # the same runtime palette. Semantic alert chips/cards are then rebuilt.
        for window in QApplication.topLevelWidgets():
            window.setStyleSheet('')
            for child in window.findChildren(QWidget): child.setStyleSheet('')
        self.brand_label.setStyleSheet(f'font-size:17pt;font-weight:800;color:{C["accent"]};padding:8px 6px')
        self.status.setStyleSheet(f"color:{C['orange'] if not (self.worker and self.worker.isRunning()) else C['green']};font-weight:700;padding:5px 8px;border:1px solid {C['orange'] if not (self.worker and self.worker.isRunning()) else C['green']};border-radius:6px")
        for value in self.cards: value.setStyleSheet(f'color:{C["text"]};font-size:18pt;font-weight:700')
        for key,color in (('hashed',C['green']),('scans',C['blue']),('compromises',C['red'])): self.telemetry_kpis[key].setStyleSheet(f'color:{color};font:bold 16pt Consolas,monospace')
        self.target.setStyleSheet(f'font-family:Consolas,monospace;background:{C["void"]};color:{C["text"]};border:1px solid {C["line"]};padding:7px')
        self._render_tree(); self._render_ledger(); self._refresh_overview(); self.donut.update(); self.area_chart.update()
        if getattr(self,'ai_report_raw',None) is not None: self.report.setHtml(forensic_report_html(self.ai_report_raw,self.selected_event))
        elif getattr(self,'selected_event',None): self.report.setHtml(self._event_summary(self.selected_event))
        self._refresh_dashboard_summary()
        self.preferences['theme']=name
        try: save_preferences(self.preferences,self.database_path.parent)
        except OSError as exc: self.statusBar().showMessage(f'Theme changed for this session; preference could not be saved: {exc}')
        parent=self.parent()
        if parent is not None and hasattr(parent,'sync_theme'): parent.sync_theme(name)
    def refresh_profiles(self,selected=None):
        if not hasattr(self,'profile'): return
        self.profile.blockSignals(True); self.profile.clear(); self.profile.addItem('No saved baseline',None)
        for p in reversed(self.state.get('profiles',[])): self.profile.addItem(f"{p['label']} · {display_timestamp(p['created'])}",p['id'])
        wanted=selected if selected is not None else self.state.get('active_id'); idx=self.profile.findData(wanted); self.profile.setCurrentIndex(max(0,idx)); self.profile.blockSignals(False)
        if hasattr(self,'history_table'): self.refresh_history()
        self._refresh_dashboard_summary()
    def refresh_history(self):
        if not hasattr(self,'history_table'): return
        table=self.history_table; table.setRowCount(0)
        for profile in reversed(self.state.get('profiles',[])):
            row=table.rowCount(); table.insertRow(row); files=profile.get('files',{}); total=sum(int(rec.get('size',0)) for rec in files.values())
            values=[profile.get('label','Baseline'),str(len(files)),f'{total/1024**2:.2f} MB',display_timestamp(profile.get('created','—')),profile.get('target','—')]
            for col,value in enumerate(values):
                item=QTableWidgetItem(value)
                item.setToolTip(str(value))
                if col==0:
                    item.setData(Qt.ItemDataRole.UserRole,profile.get('id')); item.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon))
                if col==4: item.setToolTip(str(profile.get('target','')))
                table.setItem(row,col,item)
            operations=QWidget(); operation_layout=QHBoxLayout(operations); operation_layout.setContentsMargins(2,1,2,1); operation_layout.setSpacing(4)
            audit=QPushButton('Audit'); audit.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogInfoView)); audit.setToolTip('Verify this saved baseline against current files'); audit.clicked.connect(lambda checked=False,pid=profile.get('id'):self.audit_baseline(pid)); operation_layout.addWidget(audit)
            delete=QPushButton('Delete'); delete.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon)); delete.setStyleSheet(f'color:{C["red"]};border-color:{C["red"]}'); delete.setToolTip('Delete this saved baseline'); delete.clicked.connect(lambda checked=False,pid=profile.get('id'):self.delete_baseline(pid)); operation_layout.addWidget(delete)
            table.setCellWidget(row,5,operations)
        if table.rowCount(): table.selectRow(0)
    def navigate(self,page_name):
        page=self.pages.get(page_name)
        if page is None: return
        changed=self.page_stack.currentWidget() is not page
        self.page_stack.setCurrentWidget(page)
        for name,button in self.nav_buttons.items(): button.setChecked(name==page_name)
        if changed: self._fade_in(page,150)
    def _fade_in(self,widget,duration=180):
        previous=getattr(widget,'_fim_opacity_animation',None)
        if previous is not None: previous.stop()
        effect=QGraphicsOpacityEffect(widget); effect.setOpacity(0.62); widget.setGraphicsEffect(effect)
        animation=QPropertyAnimation(effect,b'opacity',widget); animation.setDuration(duration)
        animation.setStartValue(0.62); animation.setEndValue(1.0); animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        widget._fim_opacity_animation=animation
        def clear_effect(target=widget,current_effect=effect,current_animation=animation):
            if target.graphicsEffect() is current_effect: target.setGraphicsEffect(None)
            if getattr(target,'_fim_opacity_animation',None) is current_animation: target._fim_opacity_animation=None
        animation.finished.connect(clear_effect); animation.start()
    def _update_alert_badge(self):
        badge=getattr(self,'alert_nav_badge',None)
        if badge is None: return
        active={'CREATED','TAMPERED','DELETED','RENAMED'}; seen=set()
        for event in self.events:
            kind=str(event.get('type','')).upper()
            if kind not in active: continue
            signature=event.get('signature')
            if signature is None:
                signature=(kind,event.get('old_path'),event.get('path'),event.get('time'),event.get('id'))
            try: marker=tuple(signature) if isinstance(signature,(list,tuple)) else signature
            except TypeError: marker=repr(signature)
            try: seen.add(marker)
            except TypeError: seen.add(repr(marker))
        count=len(seen)
        if count:
            badge.setText(str(count if count<100 else '99+')); badge.show()
        else:
            badge.clear(); badge.hide()
    def _refresh_dashboard_summary(self):
        if not hasattr(self,'dashboard_summary'): return
        self._update_alert_badge()
        if hasattr(self,'donut'): self.donut.update_data(self.events,self.current)
        baseline=self.active_baseline()
        scope_value,scope_detail=self.dashboard_summary['scope']; settings=self.config(); algorithms=settings.get('methods',('sha256','sha512'))
        hashed_records=[record for record in self.current.values() if record.get('status')=='hashed']
        hash_values=len(hashed_records)*len(algorithms); folders=max(0,len(getattr(self,'last_dirs',set()))-(1 if '.' in getattr(self,'last_dirs',set()) else 0))
        data_hashed=sum(int(record.get('size',0) or 0) for record in hashed_records)
        if not self.inventory_scan_valid:
            scope_value.setText('Not scanned yet'); scope_detail.setText('File, folder, hash, and data totals will appear after the first scan.')
        else:
            size_text=f'{data_hashed:,} B' if data_hashed<1024 else f'{data_hashed/1024:.1f} KB' if data_hashed<1024**2 else f'{data_hashed/1024**2:.2f} MB'
            scope_value.setText(f'{len(self.current):,} files  ·  {folders:,} subfolders'); scope_detail.setText(f'{hash_values:,} hash values  ·  {size_text} hashed  ·  {len(hashed_records):,} verified files')
        base_value,base_detail=self.dashboard_summary['baseline']
        if baseline:
            base_value.setText(baseline.get('label','Saved baseline'))
            base_detail.setText(f"Saved {display_timestamp(baseline.get('created','—'))} · {len(baseline.get('files',{})):,} records · {', '.join(str(x).upper() for x in baseline.get('methods',settings.get('methods',[])))}")
        else:
            base_value.setText('Pending first clean scan'); base_detail.setText('The first successful scan creates one trusted baseline for this target.')
        if hasattr(self,'baseline_summary'):
            if baseline:
                rows=classify_inventory_records(baseline.get('files',{}),self.current,self.current_visible,self.last_issues,settings.get('methods',('sha256','sha512')),self.inventory_scan_valid)
                counts=Counter(row.get('status') for row in rows.values())
                summary=f"Active baseline: {baseline.get('label','Saved baseline')}  ·  Saved {display_timestamp(baseline.get('created','—'))}  ·  {len(baseline.get('files',{})):,} files  ·  {', '.join(str(x).upper() for x in baseline.get('methods',settings.get('methods',[])))}"
                if self.inventory_scan_valid: summary+=f"\nLatest scan: {counts['UNCHANGED']:,} unchanged  ·  {counts['TAMPERED']:,} tampered  ·  {counts['CREATED']:,} created  ·  {counts['DELETED']:,} deleted  ·  {counts['SCAN ERROR']:,} scan errors"
                else: summary+='\nLatest scan: Not assessed yet.'
                self.baseline_summary.setText(summary)
            else: self.baseline_summary.setText('No saved baseline selected. Start monitoring to capture the first clean scan, or select a saved baseline above.')
        assessed=baseline_integrity_percentage((baseline or {}).get('files') if baseline else None,self.current,self.current_visible,self.last_issues,self.config().get('methods',('sha256','sha512')),getattr(self,'inventory_scan_valid',False))
        if assessed is None:
            self.integrity_card_value.setText('Not assessed'); self.integrity_health_dot.setStyleSheet(f'color:{C["muted"]}')
        else:
            self.integrity_card_value.setText(f'{assessed:.1f}% match'); healthy=bool(self.worker and self.worker.isRunning() and not self.last_issues and assessed>=99.0)
            self.integrity_health_dot.setStyleSheet(f'color:{C["green"] if healthy else C["orange"]}')
        integrity_value,integrity_detail=self.dashboard_summary['integrity']
        if not self.inventory_scan_valid or not baseline:
            integrity_value.setText('Not assessed'); integrity_detail.setText('A saved baseline and successful scan are required for a match-rate calculation.')
            integrity_value.setStyleSheet(f'font-size:14pt;font-weight:700;color:{C["orange"]}')
        elif self.last_issues:
            integrity_value.setText(f'{len(self.last_issues)} scan warning(s)'); integrity_detail.setText('Some paths could not be checked; their files are not classified as deleted.')
            integrity_value.setStyleSheet(f'font-size:14pt;font-weight:700;color:{C["orange"]}')
        elif self.current_visible:
            integrity_value.setText(f'{len(self.current_visible)} active difference(s)'); integrity_detail.setText('Review Alerts for created, modified, deleted, or renamed files.')
            integrity_value.setStyleSheet(f'font-size:14pt;font-weight:700;color:{C["red"]}')
        else:
            integrity_value.setText('No integrity differences'); integrity_detail.setText('The latest successful scan matches the selected trusted baseline.')
            integrity_value.setStyleSheet(f'font-size:14pt;font-weight:700;color:{C["green"]}')
        scan_value,scan_detail=self.dashboard_summary['last_scan']
        scan_value.setText(getattr(self,'last_scan_display','Not scanned yet'))
        elapsed=getattr(self,'last_scan_elapsed',None)
        memory=process_memory_mb(); memory_text=f'App memory {memory:.0f} MB' if memory is not None else 'App memory unavailable'
        scan_detail.setText((f'Completed in {elapsed:.2f} seconds  ·  {memory_text}' if elapsed is not None else f'No scan has completed for this target  ·  {memory_text}.'))
        methods=', '.join(str(method).upper() for method in settings.get('methods',('sha256','sha512')))
        exclusions=settings.get('excludes',[]); exclusions=', '.join(str(value) for value in exclusions) if exclusions else 'None'
        recursive='Every subfolder' if settings.get('recursive',True) else 'Selected folder only'
        self.dashboard_config.setHtml(f'<table width="100%" cellspacing="0" cellpadding="9"><tr><td><b>Hash algorithms</b></td><td>{escape(methods)}</td></tr><tr><td><b>Folder traversal</b></td><td>{escape(recursive)}</td></tr><tr><td><b>Automatic scan interval</b></td><td>{float(settings.get("interval",1.0)):.2f} seconds</td></tr><tr><td><b>Maximum file size</b></td><td>{float(settings.get("max_bytes",1024**3))/1024**2:,.0f} MB</td></tr><tr><td><b>Excluded names</b></td><td>{escape(exclusions)}</td></tr><tr><td><b>Baseline storage</b></td><td>{escape(str(self.database_path.parent))}</td></tr></table><p>Change these values in <b>Settings</b>. The API key is never displayed on this dashboard.</p>')
        if hasattr(self,'dashboard_activity'):
            self.dashboard_activity.clear()
            activity_icons={'TAMPERED':QStyle.StandardPixmap.SP_MessageBoxCritical,'DELETED':QStyle.StandardPixmap.SP_TrashIcon,'CREATED':QStyle.StandardPixmap.SP_FileIcon,'RENAMED':QStyle.StandardPixmap.SP_DirLinkIcon}
            for event in self.events[:12]:
                kind=str(event.get('type','FILE CHANGE')).upper(); stamp=display_timestamp(event.get('time','—')); path=str(event.get('path') or '—'); old_path=event.get('old_path')
                if kind=='RENAMED' and old_path: path=f'{old_path} → {path}'
                item=QListWidgetItem(f'{kind}   ·   {stamp}\n{path}'); icon=activity_icons.get(kind,QStyle.StandardPixmap.SP_MessageBoxInformation); item.setIcon(self.style().standardIcon(icon)); item.setForeground(QColor(EVENT_COLORS.get(kind,C['muted']))); item.setToolTip(str(event.get('detail',''))); item.setData(Qt.ItemDataRole.UserRole,event.get('id')); self.dashboard_activity.addItem(item)
            if not self.events:
                item=QListWidgetItem('No file changes recorded yet.'); item.setFlags(Qt.ItemFlag.NoItemFlags); self.dashboard_activity.addItem(item)
        if not hasattr(self,'dashboard_diagnostics'): return
        if self.last_issues:
            entries=''.join(f'<li><b>{escape(str(issue.get("path",".")))}</b><br>{escape(str(issue.get("error","Scan error")))}</li>' for issue in self.last_issues[:40])
            more=f'<p>And {len(self.last_issues)-40} additional warning(s).</p>' if len(self.last_issues)>40 else ''
            self.dashboard_diagnostics.setHtml(f'<p><b>Incomplete scan:</b> inaccessible or changing paths remain uncertain and are not treated as deletions.</p><ul>{entries}</ul>{more}')
        elif self.inventory_scan_valid:
            self.dashboard_diagnostics.setHtml('<h3>Scan completed successfully</h3><p>The selected target was enumerated without access errors. File differences are evaluated against the saved baseline; detected changes appear in Alerts.</p><p>Use the <b>Scan analytics</b> tab for hash throughput and scan trends, or <b>System Inventory</b> for file-level hashes and status.</p>')
        else:
            self.dashboard_diagnostics.setHtml('<h3>Before the first scan</h3><ol><li>Select a file or folder above.</li><li>Start monitoring to enumerate files and calculate configured hashes.</li><li>Review access warnings before trusting a missing-file result.</li></ol><p>Scan warnings are shown here and are never treated as proof that files were deleted.</p>')
    def show_inventory(self): self.navigate('System Inventory')
    def show_forensic(self): self.navigate('Forensic Analysis')
    def show_alert_center(self): self.navigate('Alerts')
    def inspect_node(self,item,column):
        self.select_inventory(item,None); self.show_forensic()
    def select_alert_item(self,current,previous):
        if current: self.select_alert(current,previous)
    def refresh_alert_center(self):
        selected=self.alert_list.currentItem(); selected_data=selected.data(Qt.ItemDataRole.UserRole) if selected else None
        selected_id=selected_data.get('id') if isinstance(selected_data,dict) else None
        animate_ids=getattr(self,'_new_alert_animation_ids',set())
        self.alert_list.blockSignals(True); self.alert_list.clear()
        for event in self.events:
            detail=f"{event.get('old_path','—')}  →  {event['path']}" if event['type']=='RENAMED' else event['path']
            size=event.get('old_size') if event['type']=='DELETED' else event.get('new_size')
            severity={'TAMPERED':'HIGH','DELETED':'HIGH','CREATED':'MEDIUM','RENAMED':'LOW'}.get(event['type'],'INFO')
            color=EVENT_COLORS.get(event['type'],C['muted']); item=QListWidgetItem(); item.setData(Qt.ItemDataRole.UserRole,event); item.setToolTip(event.get('detail','')); self.alert_list.addItem(item)
            card=QFrame(); card.setObjectName('eventCard'); card.setStyleSheet(f"QFrame#eventCard{{background:{C['panel']};border:1px solid {C['line']};border-left:4px solid {color};border-radius:6px;}}")
            box=QVBoxLayout(card); box.setContentsMargins(11,8,11,8); box.setSpacing(6)
            top=QHBoxLayout(); kind=QLabel(f"{event['type']}  ·  {severity} SEVERITY"); kind.setStyleSheet(f'color:{color};font-weight:900;letter-spacing:0.4px'); top.addWidget(kind); top.addStretch(1); when=QLabel(f"Detected  ·  {display_timestamp(event.get('time','—'))}"); when.setStyleSheet(f'color:{C["muted"]};font:9pt Consolas,monospace'); when.setToolTip('Detection time during a successful scan; the exact filesystem change time may be earlier.'); top.addWidget(when); box.addLayout(top)
            path=QLabel(detail); path.setWordWrap(True); path.setStyleSheet(f'color:{C["text"]};font-weight:800;font-family:Consolas,monospace'); box.addWidget(path)
            explanation={'TAMPERED':'The file content no longer matches the trusted baseline.', 'DELETED':'A file in the baseline was missing during a successful scan.', 'CREATED':'A new file was found inside the monitored scope.', 'RENAMED':'A matching file appears to have moved to a different path.'}
            short=[explanation.get(event['type'],'A file-system change was detected.')]
            if event['type']=='TAMPERED':
                old=event.get('old_size'); new=event.get('new_size')
                if old is not None and new is not None: short.append(f'Size changed from {old:,} to {new:,} bytes ({new-old:+,} bytes).')
                else: short.append('The saved and current cryptographic hashes differ.')
            elif event['type']=='DELETED': short.append(f'Last known size: {int(size or 0):,} bytes.')
            elif event['type']=='CREATED': short.append(f'Observed size: {int(size or 0):,} bytes.')
            elif event['type']=='RENAMED': short.append('The file contents matched at the old and new paths; the monitor cannot identify which program moved it.')
            summary=QLabel('  '.join(short)); summary.setWordWrap(True); summary.setStyleSheet(f'color:{C["muted"]};font-size:9pt'); box.addWidget(summary)
            actions=QHBoxLayout(); actions.addStretch(1); details_button=QPushButton('Details'); details_button.setToolTip('Show a concise explanation and the measured change details.'); investigate_button=QPushButton('Investigate'); investigate_button.setObjectName('primary'); investigate_button.setToolTip('Open the forensic workspace with the full technical evidence.'); actions.addWidget(details_button); actions.addWidget(investigate_button); box.addLayout(actions)
            details_button.clicked.connect(lambda checked=False,ev=dict(event):self.show_alert_details(ev)); investigate_button.clicked.connect(lambda checked=False,ev=dict(event):self.investigate_alert(ev))
            item.setSizeHint(card.sizeHint()); self.alert_list.setItemWidget(item,card)
            if event.get('id') in animate_ids: self._fade_in(card,220)
            if selected_id and event.get('id')==selected_id: self.alert_list.setCurrentItem(item)
        self.alert_list.blockSignals(False)
        self._new_alert_animation_ids=set()
        if self.alert_list.count()==0:
            empty=QListWidgetItem('No file alerts yet. Start monitoring to record and explain created, modified, deleted, or renamed files.')
            empty.setFlags(Qt.ItemFlag.NoItemFlags); empty.setForeground(QColor(C['muted'])); self.alert_list.addItem(empty)
        chat_selected=self.chat_alert_select.currentData(); chat_id=chat_selected.get('id') if isinstance(chat_selected,dict) else None
        self.chat_alert_select.blockSignals(True); self.chat_alert_select.clear()
        for event in self.events:
            if event.get('type') not in ('TAMPERED','DELETED','CREATED','RENAMED'): continue
            label=f"{event.get('type')} · {event.get('path','')} · {display_timestamp(event.get('time',''))}"
            self.chat_alert_select.addItem(label,event)
        if chat_id:
            idx=next((i for i in range(self.chat_alert_select.count()) if self.chat_alert_select.itemData(i).get('id')==chat_id),-1)
            if idx>=0: self.chat_alert_select.setCurrentIndex(idx)
        self.chat_alert_select.blockSignals(False); self._chat_alert_changed()
    def show_alert_details(self,event):
        if not isinstance(event,dict): return
        kind=event.get('type','FILE CHANGE'); path=event.get('path','—'); old_path=event.get('old_path'); old_size=event.get('old_size'); new_size=event.get('new_size')
        meanings={'TAMPERED':'The file was present, but its current hash differs from the saved trusted baseline. This confirms that its contents changed; it does not establish intent or identify who changed it.', 'DELETED':'The file was recorded in the baseline and was absent from the latest successful scan. A scan access error is not reported as a deletion.', 'CREATED':'The file was found in the monitored location but was not present in the selected baseline.', 'RENAMED':'The monitor found a matching file fingerprint at a different path. This suggests a move or rename, but does not identify the program that performed it.'}
        lines=[f"Detected: {display_timestamp(event.get('time','—'))}",f"Alert type: {kind}",f"File path: {path}",f"What happened: {meanings.get(kind,'The monitor recorded a filesystem change.')}"]
        if kind=='RENAMED': lines.append(f"Previous path: {old_path or '—'}")
        if kind=='TAMPERED' and old_size is not None and new_size is not None: lines.append(f"Size: {old_size:,} → {new_size:,} bytes ({new_size-old_size:+,} bytes)")
        elif kind=='DELETED': lines.append(f"Last known size: {int(old_size or 0):,} bytes")
        elif kind=='CREATED': lines.append(f"Observed size: {int(new_size or 0):,} bytes")
        else:
            if old_size is not None: lines.append(f"Previous size: {int(old_size):,} bytes")
            if new_size is not None: lines.append(f"Current size: {int(new_size):,} bytes")
        lines.extend(['', 'TECHNICAL EVIDENCE',f"Scan detail: {event.get('detail') or 'No additional scan detail was recorded.'}"])
        for label,old_key,new_key in (('SHA-256','old_hash','new_hash'),('SHA-512','old_sha512','new_sha512')):
            old=event.get(old_key); new=event.get(new_key)
            if old or new: lines.append(f"{label} baseline: {old or '—'}\n{label} observed: {new or '—'}")
        diff=event.get('diff') or {}; removed=diff.get('removed_lines',[]); added=diff.get('added_lines',[])
        if removed or added:
            lines.extend(['',f"Text diff: {len(removed)} removed line(s), {len(added)} added line(s)"])
            lines.extend(f"− {line}" for line in removed[:10]); lines.extend(f"+ {line}" for line in added[:10])
        dialog=QDialog(self); dialog.setWindowTitle(f'Alert details · {kind}'); dialog.resize(760,560); layout=QVBoxLayout(dialog)
        heading=QLabel(f'{kind}  ·  {Path(path).name or path}'); heading.setObjectName('dialogTitle'); heading.setWordWrap(True); layout.addWidget(heading)
        body=QPlainTextEdit(); body.setReadOnly(True); body.setPlainText('\n'.join(lines)); body.setFont(QFont('Consolas',10)); layout.addWidget(body,1)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Close); buttons.button(QDialogButtonBox.StandardButton.Close).clicked.connect(dialog.accept); layout.addWidget(buttons); dialog.setStyleSheet(APP_QSS); dialog.exec()
    def investigate_alert(self,event):
        if not isinstance(event,dict): return
        self._load_alert_forensic(event); self.show_forensic()
    def _chat_alert_changed(self,*_):
        event=self.chat_alert_select.currentData() if hasattr(self,'chat_alert_select') else None
        if not isinstance(event,dict):
            self.chat_transcript.clear(); self.chat_transcript.setPlaceholderText('No alerts yet. Start monitoring, then select an alert to begin an evidence-based chat.'); return
        self.selected_event=dict(event); turns=self.ai_chat_history.get(event.get('id'),[])
        if not turns:
            self.chat_transcript.setHtml(f'<p><b>Selected alert:</b> {escape(event.get("type",""))} · {escape(event.get("path",""))}</p><p>Ask about the observed evidence, possible impact, or investigation steps.</p>')
            return
        html=[f'<p><b>Selected alert:</b> {escape(event.get("type",""))} · {escape(event.get("path",""))}</p>']
        for turn in turns:
            html.append(f'<p><b>You:</b> {escape(turn["question"])}</p><p><b>{escape(turn.get("source","Gemini"))}:</b> {escape(turn["answer"])}</p><hr>')
        self.chat_transcript.setHtml(''.join(html))
    def clear_ai_chat(self):
        event=self.chat_alert_select.currentData()
        if isinstance(event,dict): self.ai_chat_history.pop(event.get('id'),None)
        self._chat_alert_changed()
    def ask_ai_about_alert(self):
        event=self.chat_alert_select.currentData(); question=self.chat_input.text().strip()
        if not isinstance(event,dict): QMessageBox.information(self,'Select an alert','Choose an alert before starting an alert-based AI conversation.'); return
        if not question: return
        if self.analysis_worker and self.analysis_worker.isRunning(): return
        if not self.config().get('llm_enabled'):
            QMessageBox.information(self,'Enable AI analysis','Enable Gemini and add your API key in Settings before asking about an alert.'); return
        self.selected_event={**event,'_analyst_question':question,'_chat_history':list(self.ai_chat_history.get(event.get('id'),[]))[-3:]}
        self.chat_pending_question=question; self.chat_input.clear(); self.chat_send_btn.setEnabled(False)
        self.chat_transcript.append(f'<p><b>You:</b> {escape(question)}</p><p><i>Preparing alert evidence…</i></p>')
        self.navigate('AI Assistant'); self.analyze_selected()
    def audit_selected_baseline(self):
        row=self.history_table.currentRow()
        if row<0 or not self.history_table.item(row,0): QMessageBox.information(self,'Select a baseline','Choose a saved baseline from the history registry first.'); return
        pid=self.history_table.item(row,0).data(Qt.ItemDataRole.UserRole); profile=next((p for p in self.state.get('profiles',[]) if p.get('id')==pid),None)
        if not profile: QMessageBox.warning(self,'Baseline unavailable','That saved baseline is no longer available. Refresh the registry and try again.'); return
        if self.audit_worker and self.audit_worker.isRunning(): return
        if hasattr(self,'audit_btn'): self.audit_btn.setEnabled(False); self.audit_btn.setText('Auditing files…')
        self.statusBar().showMessage(f"Running differential audit against {profile['label']}…")
        self.audit_worker=BaselineAuditWorker(profile); self.audit_worker.completed.connect(self.finish_baseline_audit); self.audit_worker.finished.connect(self._audit_finished); self.audit_worker.start()
    def _audit_finished(self):
        if hasattr(self,'audit_btn'): self.audit_btn.setEnabled(True); self.audit_btn.setText('🔬  Run differential audit against selected baseline')
    def audit_baseline(self,profile_id):
        for row in range(self.history_table.rowCount()):
            cell=self.history_table.item(row,0)
            if cell and cell.data(Qt.ItemDataRole.UserRole)==profile_id:
                self.history_table.selectRow(row); self.audit_selected_baseline(); return
        QMessageBox.warning(self,'Baseline unavailable','That snapshot no longer exists. Refresh the registry and try again.')
    def delete_baseline(self,profile_id):
        profile=next((p for p in self.state.get('profiles',[]) if p.get('id')==profile_id),None)
        if not profile: self.refresh_history(); return
        if self.audit_worker and self.audit_worker.isRunning():
            QMessageBox.information(self,'Audit in progress','Wait for the baseline audit to finish before deleting a snapshot.'); return
        prompt=QDialog(self); prompt.setWindowTitle('Permanently delete snapshot'); prompt.setMinimumWidth(440); layout=QVBoxLayout(prompt)
        title=QLabel('Delete this saved baseline permanently?'); title.setObjectName('dialogTitle'); layout.addWidget(title)
        detail=QLabel(f"{profile.get('label','Baseline')}\n{profile.get('target','')}\n{len(profile.get('files',{})):,} file records\n\nThis removes the snapshot from the authenticated baseline database. This cannot be undone."); detail.setWordWrap(True); layout.addWidget(detail)
        confirm=QCheckBox('I understand this snapshot will be permanently deleted'); layout.addWidget(confirm)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Yes|QDialogButtonBox.StandardButton.Cancel); delete_button=buttons.button(QDialogButtonBox.StandardButton.Yes); delete_button.setText('Permanently delete'); delete_button.setEnabled(False); confirm.toggled.connect(delete_button.setEnabled); buttons.accepted.connect(prompt.accept); buttons.rejected.connect(prompt.reject); layout.addWidget(buttons); prompt.setStyleSheet(APP_QSS)
        if prompt.exec()!=QDialog.DialogCode.Accepted: return
        if self.active_profile==profile_id and self.worker and self.worker.isRunning():
            self.stop_monitoring(); self.worker.wait(5000)
            if self.worker.isRunning(): QMessageBox.warning(self,'Scanner is stopping','The active scan must stop before its baseline can be deleted.'); return
        profiles=[p for p in self.state.get('profiles',[]) if p.get('id')!=profile_id]
        active=self.state.get('active_id')
        if active==profile_id: active=profiles[-1]['id'] if profiles else None
        updated={'active_id':active,'profiles':profiles}
        try: self._save_state(updated)
        except (OSError,ValueError) as exc: QMessageBox.critical(self,'Snapshot was not deleted',f'The authenticated baseline database could not be updated. {exc}'); return
        if self.active_profile==profile_id: self.active_profile=None
        self.refresh_profiles(active); self.refresh_history()
        self.statusBar().showMessage(f"Permanently deleted baseline snapshot: {profile.get('label','Baseline')}. Database authentication was recomputed.")
    def finish_baseline_audit(self,result):
        profile=result['profile']; scan=result.get('scan')
        if not scan:
            self.report.setHtml(forensic_report_html({'classification':'BASELINE AUDIT FAILED','priority':'HIGH','summary':result.get('error','The baseline could not be audited.'),'evidence_footprints':['The saved baseline was left unchanged.']},{})); self.show_forensic(); return
        events=result['events']; details=[f"Baseline: {profile['label']}",f"Target: {profile['target']}",f"Files scanned: {sum(r.get('status')=='hashed' for r in scan['files'].values())}",f"Scan warnings: {len(scan['issues'])}",f"Differences: {len(events)}"]
        details.extend(f"WARNING · {issue['path']}: {issue['error']}" for issue in scan['issues']); details.extend(f"{event['type']} · {event['path']}: {event['detail']} · {event['time']}" for event in events)
        if not events and not scan['issues']: details.append('No differences detected; files match the saved baseline.')
        audit={'classification':'BASELINE DIFFERENTIAL AUDIT','priority':'HIGH' if events else 'INFO','impact_score':len(events),'summary':'Read-only comparison completed. The selected baseline was not changed.','evidence_footprints':details,'vulnerability_breakdown':[f"{ev['type']}: {ev['path']}" for ev in events] or ['No integrity deviations were found.'],'containment_playbook':['Review each listed path and timestamp.','Investigate inaccessible scan warnings before treating missing records as deletions.','Keep the selected trusted baseline unchanged unless an analyst explicitly creates a new one.']}
        self.ai_report_raw=audit; self.selected_event=None; self.report.setHtml(forensic_report_html(audit,{})); self.node_tabs.setCurrentWidget(self.report); self.show_forensic(); self.statusBar().showMessage(f"Differential audit complete · {len(events)} alert(s), {len(scan['issues'])} warning(s). Baseline unchanged.")
    def _show_welcome(self):
        key='welcome_shown'
        if getattr(self,'_welcome',False): return
        self._welcome=True
        QMessageBox.information(self,'Welcome to SentinelFIM','SentinelFIM watches a selected file or folder. It records a trusted baseline, then alerts when files are created, changed, renamed, or deleted.\n\nChoose a target on Dashboard and select Start monitoring. Use the six sidebar destinations to open Dashboard (including scan analytics), Baseline Manager, Alerts, System Inventory, AI Assistant, or Forensic Analysis.\n\nThe System Integrity card shows the verified baseline match rate when a baseline and scan are available. It is a comparison metric, not a security guarantee. AI explanations are advisory; only selected alert metadata is sent, never file contents.')
    def pick_file(self):
        name,_=QFileDialog.getOpenFileName(self,'Choose a file',self.target.text() or str(Path.home()))
        if name: self.target.setText(name)
    def pick_folder(self):
        name=QFileDialog.getExistingDirectory(self,'Choose a folder',self.target.text() or str(Path.home()))
        if name: self.target.setText(name)
    def config(self):
        defaults={'target':self.target.text().strip(),'methods':('sha256','sha512'),'recursive':True,'max_bytes':1024**3,'interval':1.0,'excludes':DEFAULT_EXCLUDES.split(','),'llm_enabled':False,'llm_provider':'gemini','llm_model':DEFAULT_GEMINI_MODEL,'analysis_timeout_seconds':DEFAULT_ANALYSIS_TIMEOUT_SECONDS,'llm_api_key':'','llm_endpoint':'http://localhost:11434/api/chat'}
        return {**defaults,**getattr(self,'settings',{})}
    def active_baseline(self):
        pid=self.profile.currentData()
        return next((p for p in self.state.get('profiles',[]) if p['id']==pid),None)
    def start_monitoring(self):
        target=self.target.text().strip()
        if not target or not Path(target).exists(): QMessageBox.warning(self,'Choose a target','Enter or choose an existing file or folder first.'); return
        if self.worker and self.worker.isRunning(): return
        baseline=self.active_baseline()
        if baseline and os.path.normcase(os.path.abspath(baseline['target']))!=os.path.normcase(os.path.abspath(target)):
            baseline=None; self.statusBar().showMessage('Selected baseline is for a different target. A new trusted baseline will be created after a successful scan.')
        self.active_profile=baseline['id'] if baseline else None; self.current={}; self.current_visible=[]; self.inventory_scan_valid=False; self.last_issues=[]; self.last_dirs=set(); self.last_hash_stats={}; self.last_scan_display='Waiting for first scan'; self.last_scan_elapsed=None; self._render_tree(); self._refresh_dashboard_summary()
        self.worker=MonitorWorker(); self.worker.configure(self.config(),baseline); self.worker.scan_ready.connect(self.on_scan); self.worker.finished.connect(self.worker_finished); self.worker.start()
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True); self.profile.setEnabled(False); self.target.setReadOnly(True); self.status.setText('●  MONITORING ACTIVE'); self.status.setStyleSheet(f"color:{C['green']};font-weight:700;padding:7px 12px;border:1px solid {C['green']};border-radius:12px")
        self.dashboard_start_btn.setEnabled(False); self.dashboard_stop_btn.setEnabled(True)
    def stop_monitoring(self):
        if self.worker and self.worker.isRunning(): self.worker.stop(); self.status.setText('●  STOPPING SCAN STREAM'); self.status.setStyleSheet(f"color:{C['orange']};font-weight:700;padding:7px 12px;border:1px solid {C['orange']};border-radius:12px"); self.stop_btn.setEnabled(False); self.dashboard_stop_btn.setEnabled(False)
    def worker_finished(self):
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False); self.dashboard_start_btn.setEnabled(True); self.dashboard_stop_btn.setEnabled(False); self.profile.setEnabled(True); self.target.setReadOnly(False); self.status.setText('●  SCANNER: CORE AUDIT STREAM PAUSED'); self.status.setStyleSheet(f"color:{C['orange']};font-weight:700;padding:7px 12px;border:1px solid {C['orange']};border-radius:12px")
        self._refresh_dashboard_summary()
    def _profile_from_scan(self,result,label=None):
        conf=self.config(); profile={'id':uuid.uuid4().hex,'label':label or Path(conf['target']).name or conf['target'],'target':conf['target'],'created':datetime.now().astimezone().isoformat(timespec='seconds'),'recursive':conf['recursive'],'max_bytes':conf['max_bytes'],'excludes':conf['excludes'],'files':{r:public_record(v) for r,v in result['files'].items() if v['status'] in ('hashed','excluded','locked')},'methods':list(conf['methods'])}
        return profile
    def _save_state(self,state):
        save_db(self.database_path,state,self.password); self.state=state
    def _record_verified_renames(self,events):
        """Add an immutable baseline revision for moves proven byte-identical."""
        profile=next((p for p in self.state.get('profiles',[]) if p.get('id')==self.active_profile),None)
        if not profile: return
        files=dict(profile.get('files',{})); moved=[]
        for event in events:
            if event.get('type')!='RENAMED': continue
            old_path=event.get('old_path'); new_path=event.get('new_path') or event.get('path'); current=self.current.get(new_path)
            same=(bool(old_path and new_path and old_path in files and current and current.get('status')=='hashed')
                and event.get('old_hash')==event.get('new_hash')==current.get('sha256')
                and event.get('old_sha512')==event.get('new_sha512')==current.get('sha512')
                and event.get('old_size')==event.get('new_size')==current.get('size'))
            if not same: continue
            previous=files.pop(old_path); files[new_path]={**previous,**public_record(current)}; moved.append((old_path,new_path))
        if not moved: return
        now=datetime.now().astimezone().isoformat(timespec='seconds'); label=f"{profile['label']} · verified rename"
        revision={**profile,'id':uuid.uuid4().hex,'label':label,'created':now,'files':files}
        state={'active_id':revision['id'],'profiles':(self.state.get('profiles',[])+[revision])[-MAX_PROFILES:]}
        try:
            self._save_state(state); self.active_profile=revision['id']; self.refresh_profiles(revision['id'])
            if self.worker: self.worker.replace_baseline(self._memory_baseline(revision))
            self.statusBar().showMessage('Verified file rename recorded as a new baseline revision; the previous baseline and rename alert remain in history.')
        except (OSError,ValueError) as exc:
            self.statusBar().showMessage(f'File rename was detected but its baseline revision could not be saved: {exc}')
    def _memory_baseline(self,profile):
        # Persist only public metadata; keep bounded text cache in worker memory for precise diffs.
        return {**profile,'files':{rel:dict(rec) for rel,rec in self.current.items()}}
    def commit_baseline(self):
        if not self.current: QMessageBox.information(self,'No scan data','Start monitoring and wait for a successful scan before committing a baseline.'); return
        if self.last_issues: QMessageBox.warning(self,'Incomplete scan','Resolve inaccessible paths before committing a trusted baseline.'); return
        if self.current_visible:
            answer=QMessageBox.warning(self,'Authorize violations and replace baseline','This accepts the current file state, including the listed integrity violations, as trusted. The current incident indicators will be cleared and the previous baseline will remain in history. Continue?',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.Cancel,QMessageBox.StandardButton.Cancel)
            if answer!=QMessageBox.StandardButton.Yes: return
        from PyQt6.QtWidgets import QInputDialog
        label,ok=QInputDialog.getText(self,'Commit trusted baseline','Baseline name:',text=Path(self.target.text()).name)
        if not ok: return
        profile=self._profile_from_scan({'files':self.current},label.strip() or Path(self.target.text()).name)
        profiles=(self.state.get('profiles',[])+[profile])[-MAX_PROFILES:]; new={'active_id':profile['id'],'profiles':profiles}
        try: self._save_state(new)
        except (OSError,ValueError) as e: QMessageBox.critical(self,'Save failed',str(e)); return
        self.active_profile=profile['id']; self.refresh_profiles(profile['id'])
        if self.worker: self.worker.replace_baseline(self._memory_baseline(profile))
        self.events=[]; self.current_visible=[]; self._render_tree(); self._render_ledger(); self._refresh_overview()
        self.statusBar().showMessage('New trusted baseline committed. Previous baseline history is retained.')
    def change_profile(self,index):
        if not hasattr(self,'profile'): return
        pid=self.profile.currentData(); profile=next((p for p in self.state.get('profiles',[]) if p['id']==pid),None)
        if profile:
            self.target.setText(profile['target']); self.state['active_id']=pid
            try: self._save_state(self.state)
            except (OSError,ValueError) as e: QMessageBox.critical(self,'Save failed',str(e)); return
            self.refresh_history()
            # A running scan keeps its chosen immutable baseline until stopped and restarted.
            if not (self.worker and self.worker.isRunning()):
                self.current={}; self.current_visible=[]; self.last_dirs={'.'}; self.dir_info={}; self.last_issues=[]; self.last_hash_stats={}; self.last_scan_display='Not scanned yet'; self.last_scan_elapsed=None; self.inventory_scan_valid=False
            self._render_tree(); self._refresh_dashboard_summary()
        else:
            self.state['active_id']=None; self.current={}; self.current_visible=[]; self.last_dirs={'.'}; self.dir_info={}; self.last_issues=[]; self.last_hash_stats={}; self.inventory_scan_valid=False; self.last_scan_display='Not scanned yet'; self.last_scan_elapsed=None; self._render_tree(); self._refresh_dashboard_summary()
    def open_settings(self):
        config={**self.config(),'theme':self.preferences.get('theme',ACTIVE_THEME),'storage_dir':str(self.database_path.parent)}
        dialog=SettingsDialog(config,self); dialog.changePasswordRequested.connect(self.change_password)
        if dialog.exec()!=QDialog.DialogCode.Accepted: return
        values=dialog.value(); selected_theme=values.pop('theme',ACTIVE_THEME); new_dir=Path(values.pop('storage_dir')).expanduser()
        if not new_dir.is_absolute(): QMessageBox.warning(self,'Choose a valid folder','The baseline storage path must be an absolute folder path.'); return
        new_database=new_dir/'baselines.json'
        try:
            moving=os.path.normcase(str(new_database.resolve(strict=False)))!=os.path.normcase(str(self.database_path.resolve(strict=False)))
            if moving and new_database.exists():
                existing,error,_=load_db(new_database,self.password)
                if error or existing is None: raise ValueError('The selected folder already contains a baseline database that cannot be authenticated with your current password. Choose a different folder.')
                merged={p['id']:p for p in existing.get('profiles',[])}; merged.update({p['id']:p for p in self.state.get('profiles',[])})
                state={'active_id':self.state.get('active_id'),'profiles':list(merged.values())[-MAX_PROFILES:]}; save_db(new_database,state,self.password); self.state=state
            elif moving: save_db(new_database,self.state,self.password)
            preferences={**self.preferences,'theme':selected_theme,'storage_dir':str(new_dir),'monitoring':{k:v for k,v in values.items() if k not in ('llm_api_key','remember_api_key')}}
            save_preferences(preferences,new_dir)
        except (OSError,ValueError) as exc: QMessageBox.critical(self,'Settings not saved',f'Could not update the baseline storage or settings file. {exc}'); return
        key=values.get('llm_api_key',''); ok,error=store_api_key(key if values.get('remember_api_key') else '')
        self.settings=values; self.database_path=new_database; self.preferences=preferences
        self.switch_theme(selected_theme)
        self._refresh_dashboard_summary()
        if not ok: QMessageBox.warning(self,'API key not saved securely',f'The settings were saved, but the API key could not be stored in the operating-system credential vault. It will be available for this session only. {error}')
        self.statusBar().showMessage(f"Settings saved · baselines stored in {new_database.parent}")
    def change_password(self):
        dialog=QDialog(self); dialog.setWindowTitle('Change baseline database password'); layout=QVBoxLayout(dialog); layout.addWidget(QLabel('Enter your current key, then choose a new key of at least 12 characters. The baseline history will be re-authenticated with the new key.'))
        form=QFormLayout(); current=QLineEdit(); new=QLineEdit(); confirm=QLineEdit()
        for field in (current,new,confirm): field.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow('Current key',current); form.addRow('New key',new); form.addRow('Repeat new key',confirm); layout.addLayout(form); error=QLabel(); error.setObjectName('errorText'); layout.addWidget(error); buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Save|QDialogButtonBox.StandardButton.Cancel); layout.addWidget(buttons); buttons.rejected.connect(dialog.reject)
        def save_new():
            if not hmac.compare_digest(current.text(),self.password): error.setText('Current key does not match.'); return
            if len(new.text())<12 or new.text()!=confirm.text(): error.setText('Use at least 12 characters and make both new-key entries match.'); return
            try: save_db(self.database_path,self.state,new.text())
            except (OSError,ValueError) as exc: error.setText(f'Could not save the re-authenticated database: {exc}'); return
            self.password=new.text(); dialog.accept(); QMessageBox.information(self,'Password changed','Your baseline database is now protected by the new password.')
        buttons.accepted.connect(save_new); dialog.setStyleSheet(APP_QSS); dialog.exec()
    def acknowledge(self):
        item=self.ledger.currentItem() or self.missing_list.currentItem() or self.change_list.currentItem()
        if not item: return
        ev=item.data(Qt.ItemDataRole.UserRole)
        if not ev: return
        if self.worker: self.worker.acknowledge(ev['signature'])
        self.events=[x for x in self.events if x['id']!=ev['id']]; self._render_ledger(); self._render_tree(); self._refresh_dashboard_summary(); self.statusBar().showMessage(f"Acknowledged {ev['path']}. Trusted baseline is unchanged; a new distinct change remains alertable.")
    def clear_ledger(self): self.events=[]; self._render_ledger(); self._refresh_overview(); self._refresh_dashboard_summary()
    def _refresh_overview(self):
        if not hasattr(self,'donut'): return
        self.donut.update_data(self.events,self.current)
        self.top_assets.setRowCount(0)
        event_by_path={ev.get('path'):ev.get('type','—') for ev in self.events}
        for rel,record in sorted(self.current.items(),key=lambda pair:(-int(pair[1].get('size',0)),pair[0].casefold()))[:5]:
            row=self.top_assets.rowCount(); self.top_assets.insertRow(row)
            values=(rel,f"{int(record.get('size',0)):,}",event_by_path.get(rel,record.get('status','unknown').upper()))
            for col,value in enumerate(values):
                cell=QTableWidgetItem(str(value)); cell.setToolTip(str(value)); self.top_assets.setItem(row,col,cell)
                state=values[2]
                if col==2: cell.setForeground(QColor(EVENT_COLORS.get(state,C['green'] if state=='HASHED' else C['orange'] if state in ('LOCKED','EXCLUDED') else C['muted'])))
        self.recent_matrix.setRowCount(0)
        for event in self.events[:5]:
            row=self.recent_matrix.rowCount(); self.recent_matrix.insertRow(row); path=event.get('old_path',event.get('path','')) if event.get('type')=='RENAMED' else event.get('path','')
            values=(display_timestamp(event.get('time','')).split(' · ')[-1],event.get('type',''),path)
            for col,value in enumerate(values):
                cell=QTableWidgetItem(str(value)); cell.setToolTip(str(value)); self.recent_matrix.setItem(row,col,cell)
                if col==1: cell.setForeground(QColor(EVENT_COLORS.get(value,C['muted'])))
    def select_inventory(self,current,previous):
        if not current: return
        rec=current.data(0,Qt.ItemDataRole.UserRole)
        if not isinstance(rec,dict): return
        def stamp(ns):
            if ns is None: return 'Unavailable'
            try: return datetime.fromtimestamp(ns/1_000_000_000).astimezone().isoformat(sep=' ',timespec='seconds')
            except (OSError,OverflowError,ValueError): return 'Unavailable'
        lines=['NODE REGISTER',f"Name       : {rec.get('name','—')}",f"Kind       : {rec.get('kind','File')}",f"State      : {rec.get('state',rec.get('status','—')).upper()}",f"Absolute   : {rec.get('absolute','—')}",f"Relative   : {rec.get('relative','—')}",f"Size       : {rec.get('size',0):,} bytes",f"Created    : {stamp(rec.get('created_ns'))}",f"Modified   : {stamp(rec.get('mtime_ns'))}",f"SHA-256    : {rec.get('sha256') or '—'}",f"SHA-512    : {rec.get('sha512') or '—'}"]
        if rec.get('error'): lines.extend(['','DIAGNOSTIC',rec['error']])
        self.inspector.setPlainText('\n'.join(lines))
        rel=rec.get('relative')
        ev=next((e for e in self.current_visible if e.get('path')==rel or e.get('old_path')==rel),None)
        if ev:
            self.selected_event=ev; self.ai_report_raw=self.analysis_results.get(ev.get('id')); self.report.setHtml(forensic_report_html(self.ai_report_raw,ev) if self.ai_report_raw else self._event_summary(ev)); self.node_tabs.setCurrentWidget(self.report)
    def _event_summary(self,ev):
        return forensic_report_html(None,ev)
    def select_alert(self,current,previous):
        if not current: return
        ev=current.data(Qt.ItemDataRole.UserRole)
        if not isinstance(ev,dict): return
        self._load_alert_forensic(ev)
    def _load_alert_forensic(self,ev):
        self.selected_event=dict(ev); self.ai_report_raw=self.analysis_results.get(ev.get('id')); self.report.setHtml(forensic_report_html(self.ai_report_raw,ev) if self.ai_report_raw else self._event_summary(ev)); self.node_tabs.setCurrentWidget(self.report)
        rel=ev.get('path'); rec=self.current.get(rel) or self.current.get(ev.get('old_path'))
        target_absolute=getattr(self,'target_absolute',self.target.text().strip()); target_kind=getattr(self,'target_kind','Folder')
        absolute=target_absolute if target_kind=='File' else str(Path(target_absolute).joinpath(*PurePosixPath(str(rel or '')).parts))
        lines=['INCIDENT NODE',f"Classification : {ev.get('type')}",f"Detected       : {display_timestamp(ev.get('time','—'))}",f"Path           : {ev.get('path')}",f"Absolute       : {absolute}",f"Details        : {ev.get('detail') or 'No additional scan detail was recorded.'}"]
        for title,old_key,new_key in (('Size (bytes)','old_size','new_size'),('SHA-256','old_hash','new_hash'),('SHA-512','old_sha512','new_sha512')):
            old=ev.get(old_key); new=ev.get(new_key)
            if old is not None or new is not None: lines.append(f'{title:15}: {old if old is not None else "—"} → {new if new is not None else "—"}')
        if rec:
            lines.extend(['', 'CURRENT FILE RECORD',f"Size           : {rec.get('size',0):,} bytes",f"SHA-256        : {rec.get('sha256') or '—'}",f"SHA-512        : {rec.get('sha512') or '—'}"])
        self.inspector.setPlainText('\n'.join(lines))
    def analyze_selected(self):
        ev=self.selected_event
        if not ev:
            QMessageBox.information(self,'Select an incident','Choose a file with an alert or an incident in the threat ledger first.'); return
        settings=self.config()
        if not settings.get('llm_enabled'):
            QMessageBox.information(self,'Analysis is disabled','Enable Gemini analysis in Settings and add your Google AI Studio API key, or choose local Ollama.'); return
        if self.analysis_worker and self.analysis_worker.isRunning(): return
        self.analysis_event=dict(ev); self.ai_buffer=''; self.ai_report_raw=None
        self.report.setHtml(forensic_report_html(local_incident_report(ev),ev)); self.node_tabs.setCurrentWidget(self.report)
        self.analysis_status.setText('Preparing a metadata-only request…'); self.analysis_status.show(); self.analysis_progress.setRange(0,0); self.analysis_progress.show(); self.analyze_btn.setEnabled(False); self.cancel_analysis_btn.setEnabled(True)
        self.analysis_worker=AnalysisWorker(settings,ev); self.analysis_worker.status.connect(self._update_analysis_status); self.analysis_worker.completed.connect(self._complete_analysis); self.analysis_worker.failed.connect(self._fail_analysis); self.analysis_worker.cancelled.connect(self._analysis_cancelled); self.analysis_worker.metrics_ready.connect(self._analysis_metrics_ready); self.analysis_worker.finished.connect(self._analysis_finished); self.analysis_worker.start()
    def _update_analysis_status(self,message,value):
        self.analysis_status.setText(message); self.analysis_progress.setValue(value)
        text=str(message).casefold()
        tone=C['green'] if any(word in text for word in ('validated','success','complete')) else C['red'] if any(word in text for word in ('failed','error')) else C['orange'] if any(word in text for word in ('unavailable','cancel')) else C['accent']
        self.analysis_status.setStyleSheet(f'background:{C["panel"]};color:{C["text"]};padding:8px;border:1px solid {C["line"]};border-left:4px solid {tone};border-radius:6px;font-family:Consolas,monospace')
    def _complete_analysis(self,report):
        ev=dict(self.analysis_event or self.selected_event or {}); self.analysis_results[ev.get('id')]=report
        if self.selected_event and self.selected_event.get('id')==ev.get('id'):
            self.ai_report_raw=report; self.report.setHtml(forensic_report_html(report,ev))
        question=ev.get('_analyst_question')
        if question:
            answer=str(report.get('technical_interpretation') or 'No interpretation was returned.')+'\n\nPotential impact: '+str(report.get('potential_impact') or 'Not available.')
            source='Gemini' if report.get('_analysis_source')=='Gemini' else 'Local rule engine'
            turns=self.ai_chat_history.setdefault(ev.get('id'),[]); turns.append({'question':question,'answer':answer,'source':source}); self.chat_pending_question=None; self._chat_alert_changed()
        self.statusBar().showMessage('Forensic analysis response validated; local detection evidence was not changed.',10000)
    def _fail_analysis(self,message):
        ev=dict(self.analysis_event or self.selected_event or {}); report=local_incident_report(ev); report['analysis_error']=message
        self.analysis_results[ev.get('id')]=report
        if self.selected_event and self.selected_event.get('id')==ev.get('id'):
            self.ai_report_raw=report; self.report.setHtml(forensic_report_html(report,ev))
        if ev.get('_analyst_question'):
            answer='AI analysis unavailable. Local evidence: '+str(report.get('technical_interpretation',''))
            self.ai_chat_history.setdefault(ev.get('id'),[]).append({'question':ev['_analyst_question'],'answer':answer,'source':'Local evidence (AI unavailable)'})
            self.chat_pending_question=None; self._chat_alert_changed()
        self.statusBar().showMessage('Analysis did not complete. See the Forensic analysis report for the error and local evidence.',10000)
    def cancel_analysis(self):
        if self.analysis_worker and self.analysis_worker.isRunning():
            self.analysis_worker.requestInterruption(); self.cancel_analysis_btn.setEnabled(False)
            timeout=max(MIN_ANALYSIS_TIMEOUT_SECONDS,min(MAX_ANALYSIS_TIMEOUT_SECONDS,int(self.settings.get('analysis_timeout_seconds',DEFAULT_ANALYSIS_TIMEOUT_SECONDS))))
            self.analysis_status.setText(f'Cancellation requested. Waiting for the current API call to finish or time out (up to {timeout} seconds)…')
    def _analysis_cancelled(self):
        if self.chat_pending_question:
            event=self.analysis_event or self.selected_event or {}; self.chat_transcript.append('<p><i>Analysis cancelled. The selected alert evidence is still available.</i></p>'); self.chat_pending_question=None
        self.statusBar().showMessage('Gemini analysis cancelled. The local forensic evidence remains available.',10000)
    def _analysis_metrics_ready(self,metrics):
        first=metrics.get('first_response_ms'); first_text=f"; first response {first/1000:.1f}s" if isinstance(first,int) else ''
        started=metrics.get('request_started_at'); started_text=f"; started {started}" if started else ''
        self.statusBar().showMessage(f"Analysis timing: preparation {metrics.get('preparation_ms',0)/1000:.2f}s; request {metrics.get('request_ms',0)/1000:.2f}s{first_text}; retries {metrics.get('retry_count',0)}; total {metrics.get('total_ms',0)/1000:.2f}s{started_text}",15000)
    def _analysis_finished(self):
        self.analysis_progress.setRange(0,100); self.analysis_progress.setValue(0); self.analysis_progress.hide(); self.analysis_status.hide(); self.analyze_btn.setEnabled(True); self.cancel_analysis_btn.setEnabled(False)
        if hasattr(self,'chat_send_btn'): self.chat_send_btn.setEnabled(True)
    def on_scan(self,result):
        self.active_scans_run+=1; self.total_compromises+=sum(ev.get('type') in ('TAMPERED','DELETED') for ev in result.get('new_events',[]))
        self._new_alert_animation_ids={ev.get('id') for ev in result.get('new_events',[]) if ev.get('id')}
        self.current=result['files']; self.last_issues=result['issues']; self.last_dirs=result['directories']; self.dir_info=result.get('directory_info',{}); self.target_absolute=result.get('absolute_target',self.target.text().strip()); self.target_kind=self.dir_info.get('.',{}).get('kind','Target'); self.current_visible=result['events']; self.last_hash_stats=result.get('hash_stats',{}); self.inventory_scan_valid=bool(self.current or self.last_dirs or not self.last_issues); self.last_scan_display=datetime.now().astimezone().strftime('%I:%M:%S %p'); self.last_scan_elapsed=float(result.get('elapsed',0.0))
        if result.get('baseline_missing') and not result['issues']:
            scan_target=result.get('absolute_target') or self.target.text().strip()
            target_key=os.path.normcase(os.path.abspath(scan_target))
            existing=self.active_baseline()
            if not existing or os.path.normcase(os.path.abspath(existing.get('target','')))!=target_key:
                existing=initial_baseline_for_target(self.state.get('profiles',[]),scan_target)
            # The scan signal is queued to the UI thread. A fast next scan may already
            # have captured baseline_missing=True before the first save completed.
            # Reuse the saved target snapshot instead of creating a second copy.
            if existing and os.path.normcase(os.path.abspath(existing.get('target','')))==target_key:
                self.active_profile=existing['id']
                self.state['active_id']=existing['id']
                if self.profile.currentData()!=existing['id']:
                    self.refresh_profiles(existing['id'])
                    try: self._save_state(self.state)
                    except (OSError,ValueError) as e: self.statusBar().showMessage(f'Using the existing baseline for this session; its active selection could not be saved: {e}')
                if self.worker: self.worker.replace_baseline(existing)
                self.statusBar().showMessage('Initial baseline already saved for this target; continuing against that snapshot.')
            else:
                profile=self._profile_from_scan(result,'Initial baseline · '+(Path(self.target.text()).name or 'target'))
                new={'active_id':profile['id'],'profiles':(self.state.get('profiles',[])+[profile])[-MAX_PROFILES:]}
                try:
                    self._save_state(new); self.active_profile=profile['id']; self.refresh_profiles(profile['id'])
                    if self.worker: self.worker.replace_baseline(profile)
                    self.statusBar().showMessage('Initial trusted baseline saved. Monitoring changes against this fixed snapshot.')
                except (OSError,ValueError) as e: self.statusBar().showMessage(f'Baseline save failed: {e}')
        self._record_verified_renames(result.get('new_events',[]))
        for ev in result['new_events']:
            self.events.insert(0,ev); self.events=self.events[:MAX_ALERTS]; QApplication.beep()
        self.last_dirs=result['directories']; self._render_tree(); self._render_ledger(); self._refresh_dashboard_summary()
        if result['new_events']: self.navigate('Alerts')
        hashed=sum(1 for r in self.current.values() if r['status']=='hashed'); data=sum(r['size'] for r in self.current.values() if r['status']=='hashed')
        self.telemetry_kpis['hashed'].setText(f'{hashed:,}'); self.telemetry_kpis['scans'].setText(f'{self.active_scans_run:,}'); self.telemetry_kpis['compromises'].setText(f'{self.total_compromises:,}')
        self.area_chart.add_sample(hashed,len(self.events)); self._refresh_overview()
        if data<1024: data_text=f'{data:,} B'
        elif data<1024**2: data_text=f'{data/1024:.2f} KB'
        elif data<1024**3: data_text=f'{data/1024**2:.2f} MB'
        else: data_text=f'{data/1024**3:.3f} GB'
        stats=self.last_hash_stats; self.cards[0].setText(str(hashed)); self.cards[1].setText(str(hashed*len(self.config().get('methods',('sha256','sha512'))))); self.cards[2].setText(data_text); self.cards[3].setText(str(len(self.current_visible))); self.cards[4].setText(f"{(stats.get('bytes',0)/1024**2/max(stats.get('sha256_seconds',0),1e-9)):.1f} MB/s" if stats.get('sha256_seconds') else '0.0 MB/s'); self.cards[5].setText(f"{(stats.get('bytes',0)/1024**2/max(stats.get('sha512_seconds',0),1e-9)):.1f} MB/s" if stats.get('sha512_seconds') else '0.0 MB/s')
        issue_note=f" · {len(self.last_issues)} scan warning(s)" if self.last_issues else ''
        self.statusBar().showMessage(f"Scan {result['elapsed']:.2f}s · {hashed} files hashed · {len(result['directories'])} folders · {len(self.events)} recent alert(s){issue_note}")
    def _set_tree_status(self,item,state):
        state=state.upper(); light=ACTIVE_THEME in LIGHT_THEMES
        colors={'TAMPERED':('#fee2e2' if light else '#7f1d1d',C['red'] if light else '#fee2e2'),'DELETED':('#f3e8ff' if light else '#581c87',C['purple'] if light else '#f3e8ff'),'CREATED':('#dbeafe' if light else '#1e40af',C['blue'] if light else '#dbeafe'),'RENAMED':('#cffafe' if light else '#164e63',C['blue'] if light else '#a5f3fc'),'UNCHANGED':('#dcfce7' if light else '#064e3b',C['green'] if light else '#a7f3d0'),'SCAN ERROR':('#fef3c7' if light else '#78350f',C['orange'] if light else '#fef3c7'),'FOLDER':(C['row_alt'],C['text']),'MONITORED':(C['row_alt'],C['text']),'TAMPERED PATH':('#fee2e2' if light else '#3b151b',C['red'] if light else '#fecaca'),'DELETED PATH':('#f3e8ff' if light else '#3b2350',C['purple'] if light else '#e9d5ff'),'CREATED PATH':('#dbeafe' if light else '#172554',C['blue'] if light else '#bfdbfe'),'RENAMED PATH':('#cffafe' if light else '#143843',C['blue'] if light else '#a5f3fc'),'SCAN ERROR PATH':('#fef3c7' if light else '#3b2a0d',C['orange'] if light else '#fde68a'),'ALERT PATH':('#fee2e2' if light else '#3b151b',C['red'] if light else '#fecaca')}
        _background,foreground=colors.get(state,('#1f2937','#cbd5e1'))
        marker={'TAMPERED':'✖','DELETED':'−','CREATED':'+','RENAMED':'↗','UNCHANGED':'✓','SCAN ERROR':'!','FOLDER':'▸','MONITORED':'●'}.get(state.replace(' PATH',''),'•')
        display_state=state.replace(' PATH','')
        item.setText(4,f'{marker}  {display_state}')
        item.setForeground(4,QColor(foreground))
        explanations={'TAMPERED':'Hash differs from the saved trusted baseline.','DELETED':'File is missing from the latest successful scan.','CREATED':'File is present but was not in the saved baseline.','UNCHANGED':'Current hash matches the saved baseline.','SCAN ERROR':'The scan could not verify this path.','FOLDER':'Folder status follows its nested file states.','MONITORED':'Selected monitoring target.'}
        item.setToolTip(4,explanations.get(display_state,display_state))
        return None
    def _filter_inventory(self,*_):
        if not hasattr(self,'tree') or not hasattr(self,'inventory_filter'): return
        selected=self.inventory_filter.currentData()
        def visit(item):
            data=item.data(0,Qt.ItemDataRole.UserRole); state=data.get('state','') if isinstance(data,dict) else ''
            own=selected in (None,'ALL') or state==selected
            descendant=False
            for index in range(item.childCount()): descendant=visit(item.child(index)) or descendant
            item.setHidden(not (own or descendant))
            return own or descendant
        for index in range(self.tree.topLevelItemCount()): visit(self.tree.topLevelItem(index))
    def _render_tree(self):
        expanded={}; selected=self.tree.currentItem(); selected_data=selected.data(0,Qt.ItemDataRole.UserRole) if selected else None; selected_rel=selected_data.get('relative') if isinstance(selected_data,dict) else None
        def remember(item):
            data=item.data(0,Qt.ItemDataRole.UserRole); rel=data.get('relative') if isinstance(data,dict) else None
            if rel is not None: expanded[rel]=item.isExpanded()
            for idx in range(item.childCount()): remember(item.child(idx))
        for idx in range(self.tree.topLevelItemCount()): remember(self.tree.topLevelItem(idx))
        baseline=self.active_baseline(); baseline_files=baseline.get('files',{}) if baseline else None
        rows=classify_inventory_records(baseline_files,self.current,self.current_visible,self.last_issues,self.config().get('methods',('sha256','sha512')),getattr(self,'inventory_scan_valid',False))
        self.tree.blockSignals(True); self.tree.clear(); target=Path(self.target.text().strip() or '.')
        root_name=target.name or str(target); root=QTreeWidgetItem([root_name,'',f'{len(self.current)} files','','MONITORED']); root.setIcon(0,self.style().standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)); self.tree.addTopLevelItem(root); root.setExpanded(True)
        root_meta=getattr(self,'dir_info',{}).get('.',{}); absolute_root=Path(getattr(self,'target_absolute',str(target)))
        root.setData(0,Qt.ItemDataRole.UserRole,{'name':root_name,'kind':root_meta.get('kind','Target'),'absolute':str(absolute_root),'relative':'.','status':'monitored','state':'MONITORED',**root_meta}); self._set_tree_status(root,'MONITORED')
        folders={'.':root}; nodes_by_rel={'.':root}; priority={'TAMPERED':5,'SCAN ERROR':4,'DELETED':3,'CREATED':2,'RENAMED':1}; flagged={}
        for rel,row in rows.items():
            state=row['status']; parent=PurePosixPath(rel).parent.as_posix()
            while True:
                if priority.get(state,0)>priority.get(flagged.get(parent,''),0): flagged[parent]=state
                if parent in ('','.'): break
                parent=PurePosixPath(parent).parent.as_posix()
        self.alert_tree_items=[]
        all_dirs=set(getattr(self,'last_dirs',{'.'}))|{'.'}
        for rel in sorted(all_dirs,key=lambda p:(p.count('/'),p.casefold())):
            if rel=='.': continue
            parent_rel=PurePosixPath(rel).parent.as_posix(); parent=folders.get(parent_rel,root); absolute=absolute_root.joinpath(*PurePosixPath(rel).parts); issue=next((str(x.get('error') or '') for x in self.last_issues if str(x.get('path') or '.')==rel and 'watcher unavailable' not in str(x.get('error') or '').lower()),None)
            path_state='SCAN ERROR' if issue else flagged.get(rel,'FOLDER')
            size=sum(int(record.get('size',0) or 0) for child,record in self.current.items() if child.startswith(rel.rstrip('/')+'/'))
            item=QTreeWidgetItem([PurePosixPath(rel).name,rel,f'{size:,}','—',path_state]); folder_icon=QStyle.StandardPixmap.SP_MessageBoxWarning if issue else QStyle.StandardPixmap.SP_DirIcon; item.setIcon(0,self.style().standardIcon(folder_icon)); parent.addChild(item); folders[rel]=item; nodes_by_rel[rel]=item
            meta=getattr(self,'dir_info',{}).get(rel,{})
            item.setData(0,Qt.ItemDataRole.UserRole,{'name':PurePosixPath(rel).name,'kind':'Folder','absolute':str(absolute),'relative':rel,'status':path_state,'state':'SCAN ERROR' if issue else path_state,**meta,'error':issue})
            self._set_tree_status(item,path_state)
            if issue: item.setToolTip(0,issue)
            if rel in flagged or issue: self.alert_tree_items.append(item)
        state_icons={'TAMPERED':QStyle.StandardPixmap.SP_MessageBoxCritical,'DELETED':QStyle.StandardPixmap.SP_TrashIcon,'CREATED':QStyle.StandardPixmap.SP_FileIcon,'RENAMED':QStyle.StandardPixmap.SP_DirLinkIcon,'UNCHANGED':QStyle.StandardPixmap.SP_DialogApplyButton,'SCAN ERROR':QStyle.StandardPixmap.SP_MessageBoxWarning}
        for rel,row in sorted(rows.items(),key=lambda pair:pair[0].casefold()):
            rec=row['record']; state=row['status']; event=row.get('event'); name=PurePosixPath(rel).name
            absolute=absolute_root if getattr(self,'target_kind','Target')=='File' else absolute_root.joinpath(*PurePosixPath(rel).parts)
            sha=rec.get('sha256') if state not in ('DELETED','SCAN ERROR') or rec.get('sha256') else None
            item=QTreeWidgetItem([name,rel,f"{int(rec.get('size',0) or 0):,}",str(sha or '—'),state]); item.setIcon(0,self.style().standardIcon(state_icons.get(state,QStyle.StandardPixmap.SP_FileIcon))); parent=folders.get(PurePosixPath(rel).parent.as_posix(),root); parent.addChild(item)
            item.setData(0,Qt.ItemDataRole.UserRole,{**rec,'name':name,'kind':'Missing file' if state=='DELETED' else 'File','absolute':str(absolute),'relative':rel,'state':state,'status':state.lower(),'error':row.get('error')})
            self._set_tree_status(item,state); nodes_by_rel[rel]=item
            if state in ('TAMPERED','DELETED','CREATED','RENAMED','SCAN ERROR'): self.alert_tree_items.append(item)
            if event: item.setToolTip(0,f"{event.get('type')} · {display_timestamp(event.get('time',''))}\n{event.get('detail','')}")
            elif row.get('error'): item.setToolTip(0,row['error'])
        # Keep scan diagnostics visible even when the failed path has no known file row.
        diagnostic_paths=set()
        for issue in self.last_issues:
            rel=str(issue.get('path') or '.').replace('\\','/').strip('/') or '.'; message=str(issue.get('error') or '')
            if 'watcher unavailable' in message.lower(): continue
            if rel in diagnostic_paths: continue
            diagnostic_paths.add(rel)
            if rel in nodes_by_rel:
                if message: nodes_by_rel[rel].setToolTip(0,message)
                continue
            parent_rel=PurePosixPath(rel).parent.as_posix(); parent=folders.get(parent_rel,root)
            diagnostic=QTreeWidgetItem(['Scan access issue',rel,'','', 'SCAN ERROR']); diagnostic.setIcon(0,self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning)); diagnostic.setData(0,Qt.ItemDataRole.UserRole,{'name':'Scan access issue','kind':'Diagnostic','absolute':str(absolute_root.joinpath(*PurePosixPath(rel).parts)),'relative':rel,'state':'SCAN ERROR','status':'scan error','error':message}); diagnostic.setToolTip(0,message); parent.addChild(diagnostic); self._set_tree_status(diagnostic,'SCAN ERROR')
        for rel,state in flagged.items():
            node=folders.get(rel)
            if not node: continue
            color={'TAMPERED':C['red'],'SCAN ERROR':C['orange'],'DELETED':C['purple'],'CREATED':C['blue'],'RENAMED':C['blue']}.get(state,C['muted'])
            for col in range(4): node.setForeground(col,QColor(color))
            font=node.font(0); font.setBold(True); node.setFont(0,font); node.setToolTip(0,f'{state} status exists in this folder or one of its descendants.')
        if flagged:
            root_state=flagged.get('.',next((flagged.get(k) for k in sorted(flagged,key=lambda x:(x.count('/'),x)) if flagged.get(k)), 'MONITORED'))
            if root_state!='MONITORED': root.setText(4,f'{root_state} PATH'); self._set_tree_status(root,f'{root_state} PATH')
        for rel,node in nodes_by_rel.items():
            if rel in expanded and node is not root: node.setExpanded(expanded[rel])
        if selected_rel in nodes_by_rel: self.tree.setCurrentItem(nodes_by_rel[selected_rel])
        self.tree.blockSignals(False); self._filter_inventory()

    def _render_ledger(self):
        self.refresh_alert_center()
    def closeEvent(self,event):
        if self.worker and self.worker.isRunning():
            self.worker.stop(); self.worker.wait(5000)
            if self.worker.isRunning(): QMessageBox.warning(self,'Scan still running','Wait for the current filesystem scan to finish before closing.'); event.ignore(); return
        for worker,title in ((self.analysis_worker,'Threat analysis'),(self.audit_worker,'Baseline audit')):
            if worker and worker.isRunning(): QMessageBox.information(self,f'{title} in progress',f'Wait for the active {title.lower()} to finish before closing this panel.'); event.ignore(); return
        event.accept()
def main():
    if os.name=='nt':
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('enterprise.cybersec.file_integrity_monitor.v1')
        except (AttributeError,OSError): pass
    app=QApplication(sys.argv); app.setApplicationName('File Integrity Monitor'); app.setApplicationDisplayName('File Integrity Monitor'); app.setWindowIcon(app_icon()); app.setStyle('Fusion')
    preferences=load_preferences(); set_theme(preferences.get('theme','dark')); app.setStyleSheet(APP_QSS); path=db_path(); gate=KeyDialog(path)
    if gate.exec()!=QDialog.DialogCode.Accepted: return 0
    window=MainWindow(gate.state,gate.password,path,preferences); window.show(); return app.exec()
if __name__=='__main__': raise SystemExit(main())
