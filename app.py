# app.py
"""
Streamlit Password Vault (Multi-user Demo)
- Multi-user: Register / Login
- User passwords hashed with bcrypt (stored in users.json)
- Each user has vaults/<username>.json (salt + token) encrypted with Fernet derived from user's password
- NOT for production without improvements (external DB, KMS, HTTPS, ...)
"""

import streamlit as st
from pathlib import Path
import json, os, base64, uuid, datetime, secrets, string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import bcrypt

# -------- Config --------
USERS_FILE = Path("users.json")   # DO NOT commit to repo
VAULTS_DIR = Path("vaults")      # DO NOT commit to repo
KDF_ITERATIONS = 390_000
SALT_LEN = 16

# -------- Utility: KDF + Fernet --------
def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)

def encrypt_entries(key: bytes, entries: list) -> str:
    f = Fernet(key)
    raw = json.dumps(entries, ensure_ascii=False).encode("utf-8")
    token = f.encrypt(raw)
    return token.decode("utf-8")

def decrypt_entries(key: bytes, token_str: str) -> list:
    f = Fernet(key)
    raw = f.decrypt(token_str.encode("utf-8"))
    return json.loads(raw.decode("utf-8"))

# -------- Users file ops (hashed passwords) --------
def load_users():
    if not USERS_FILE.exists():
        return {}
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except:
        return {}

def save_users(users: dict):
    with USERS_FILE.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

# -------- Vault file ops (per-user) --------
def user_vault_path(username: str) -> Path:
    return VAULTS_DIR / f"{username}.json"

def create_user_vault(username: str, password: str):
    VAULTS_DIR.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    token = encrypt_entries(key, [])
    vault_obj = {"salt": base64.b64encode(salt).decode("utf-8"), "token": token}
    with user_vault_path(username).open("w", encoding="utf-8") as f:
        json.dump(vault_obj, f, indent=2, ensure_ascii=False)
    return salt, key

def load_user_vault(username: str, password: str):
    p = user_vault_path(username)
    if not p.exists():
        # create empty vault automatically
        salt, key = create_user_vault(username, password)
        return [], salt, key
    vault_obj = json.loads(p.read_text(encoding="utf-8"))
    salt = base64.b64decode(vault_obj["salt"].encode("utf-8"))
    key = derive_key(password, salt)
    entries = decrypt_entries(key, vault_obj["token"])
    return entries, salt, key

def save_user_vault(username: str, salt: bytes, token_str: str):
    VAULTS_DIR.mkdir(parents=True, exist_ok=True)
    vault_obj = {"salt": base64.b64encode(salt).decode("utf-8"), "token": token_str}
    with user_vault_path(username).open("w", encoding="utf-8") as f:
        json.dump(vault_obj, f, indent=2, ensure_ascii=False)

# -------- Entry helpers --------
def make_entry(site, username, password, notes=""):
    return {
        "id": str(uuid.uuid4()),
        "site": site,
        "username": username,
        "password": password,
        "notes": notes,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "modified_at": datetime.datetime.utcnow().isoformat() + "Z"
    }

def update_modified(entry):
    entry["modified_at"] = datetime.datetime.utcnow().isoformat() + "Z"

def gen_password(length=16, use_symbols=True):
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>/?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# -------- Streamlit UI & logic --------
st.set_page_config(page_title="Password Vault (Multi-user Demo)", page_icon="🔐", layout="wide")
st.title("🔐 Password Vault — Đa người dùng (Demo)")

if "user" not in st.session_state:
    st.session_state.user = None
if "password_plain" not in st.session_state:
    st.session_state.password_plain = None
if "entries" not in st.session_state:
    st.session_state.entries = []
if "key" not in st.session_state:
    st.session_state.key = None
if "salt" not in st.session_state:
    st.session_state.salt = None
if "show_pw" not in st.session_state:
    st.session_state.show_pw = {}

# ---------- If not logged in: show tabs Đăng nhập / Đăng ký ----------
if not st.session_state.user:
    tabs = st.tabs(["Đăng nhập", "Đăng ký"])
    # ---- Đăng nhập ----
    with tabs[0]:
        st.subheader("Đăng nhập")
        with st.form("login_form"):
            login_username = st.text_input("Tên đăng nhập")
            login_password = st.text_input("Mật khẩu", type="password")
            submitted = st.form_submit_button("Đăng nhập")
            if submitted:
                users = load_users()
                if login_username not in users:
                    st.error("Không tìm thấy tài khoản.")
                else:
                    stored_hash = users[login_username]["pw"]
                    if bcrypt.checkpw(login_password.encode(), stored_hash.encode()):
                        # success: load vault
                        try:
                            entries, salt, key = load_user_vault(login_username, login_password)
                            st.session_state.user = login_username
                            st.session_state.password_plain = login_password
                            st.session_state.entries = entries
                            st.session_state.key = key
                            st.session_state.salt = salt
                            st.success("Đăng nhập thành công.")
                            st.experimental_rerun()
                        except Exception as e:
                            st.error(f"Lỗi khi mở vault: {e}")
                    else:
                        st.error("Mật khẩu không đúng.")
    # ---- Đăng ký ----
    with tabs[1]:
        st.subheader("Đăng ký tài khoản mới")
        with st.form("register_form"):
            reg_username = st.text_input("Tên đăng nhập (không dấu/spaces)")
            reg_password = st.text_input("Mật khẩu (ít nhất 8 ký tự)", type="password")
            reg_password2 = st.text_input("Xác nhận mật khẩu", type="password")
            submitted_r = st.form_submit_button("Tạo tài khoản")
            if submitted_r:
                if not reg_username or not reg_password:
                    st.error("Vui lòng điền đủ thông tin.")
                elif reg_password != reg_password2:
                    st.error("Xác nhận mật khẩu không khớp.")
                elif len(reg_password) < 8:
                    st.error("Mật khẩu nên có ít nhất 8 ký tự.")
                else:
                    users = load_users()
                    if reg_username in users:
                        st.error("Tên đăng nhập đã tồn tại. Chọn tên khác.")
                    else:
                        # hash password
                        hashed = bcrypt.hashpw(reg_password.encode(), bcrypt.gensalt()).decode()
                        users[reg_username] = {"pw": hashed, "created_at": datetime.datetime.utcnow().isoformat() + "Z"}
                        save_users(users)
                        # create initial vault encrypted with this password
                        create_user_vault(reg_username, reg_password)
                        st.success("Tạo tài khoản thành công. Hãy đăng nhập.")
    st.stop()  # stop here until login
# ---------- Logged in ----------
st.sidebar.success(f"Đang đăng nhập: {st.session_state.user}")
if st.sidebar.button("Đăng xuất"):
    # remove sensitive session data
    st.session_state.user = None
    st.session_state.password_plain = None
    st.session_state.key = None
    st.session_state.salt = None
    st.session_state.entries = []
    st.experimental_rerun()

# Change password (re-encrypt vault)
with st.expander("Đổi mật khẩu (sẽ re-encrypt vault)"):
    cur_pw = st.text_input("Mật khẩu hiện tại", type="password", key="curpw")
    new_pw = st.text_input("Mật khẩu mới", type="password", key="newpw")
    new_pw2 = st.text_input("Xác nhận mật khẩu mới", type="password", key="newpw2")
    if st.button("Thực hiện đổi mật khẩu"):
        users = load_users()
        uname = st.session_state.user
        if uname not in users:
            st.error("Tài khoản không tồn tại (lỗi).")
        elif not bcrypt.checkpw(cur_pw.encode(), users[uname]["pw"].encode()):
            st.error("Mật khẩu hiện tại không đúng.")
        elif new_pw != new_pw2:
            st.error("Xác nhận mật khẩu mới không khớp.")
        elif len(new_pw) < 8:
            st.error("Mật khẩu mới nên >= 8 ký tự.")
        else:
            # re-encrypt vault with new password
            try:
                # current entries from session
                entries = st.session_state.entries
                new_salt = os.urandom(SALT_LEN)
                new_key = derive_key(new_pw, new_salt)
                new_token = encrypt_entries(new_key, entries)
                save_user_vault(uname, new_salt, new_token)
                # update users hash
                users[uname]["pw"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                save_users(users)
                # update session
                st.session_state.password_plain = new_pw
                st.session_state.key = new_key
                st.session_state.salt = new_salt
                st.success("Đổi mật khẩu thành công.")
            except Exception as e:
                st.error(f"Lỗi khi đổi mật khẩu: {e}")

st.markdown("---")
st.header("Vault cá nhân")
search_q = st.text_input("Tìm kiếm site/username (nhấn Enter để lọc)")

# Upload/Restore vault (user-scoped)
with st.expander("Upload (Restore) vault của bạn (file JSON mã hóa)"):
    uploaded = st.file_uploader("Tải file vault lên để restore (ghi đè vault của bạn)", type=["json"])
    if uploaded is not None:
        try:
            bytes_data = uploaded.getvalue()
            parsed = json.loads(bytes_data.decode("utf-8"))
            # validate minimal keys
            if "salt" in parsed and "token" in parsed:
                # overwrite user's vault file
                with user_vault_path(st.session_state.user).open("w", encoding="utf-8") as f:
                    json.dump(parsed, f, indent=2, ensure_ascii=False)
                # reload entries
                entries, salt, key = load_user_vault(st.session_state.user, st.session_state.password_plain)
                st.session_state.entries = entries
                st.session_state.salt = salt
                st.session_state.key = key
                st.success("Restore thành công.")
                st.experimental_rerun()
            else:
                st.error("File không hợp lệ.")
        except Exception as e:
            st.error(f"Lỗi khi restore: {e}")

# Download vault
p = user_vault_path(st.session_state.user)
if p.exists():
    with p.open("rb") as f:
        vault_bytes = f.read()
    st.download_button("Tải vault (đã mã hóa) của bạn", data=vault_bytes, file_name=f"{st.session_state.user}_vault.json", mime="application/json")

# Add new entry form
st.subheader("Thêm mật khẩu mới")
with st.form("add_form", clear_on_submit=True):
    site = st.text_input("Site / App")
    uname = st.text_input("Username / Email")
    pw_col1, pw_col2, pw_col3 = st.columns([2,2,1])
    with pw_col1:
        password = st.text_input("Password")
    with pw_col2:
        pw_len = st.selectbox("Độ dài", [8,12,16,24,32], index=2)
        use_symbols = st.checkbox("Có ký tự đặc biệt", value=True)
        if st.button("Sinh mật khẩu"):
            gen = gen_password(pw_len, use_symbols)
            st.session_state._generated_password = gen
            st.experimental_rerun()
    with pw_col3:
        st.write("")
        st.write("")
        st.form_submit_button("Thêm vào Vault")
    notes = st.text_area("Ghi chú (tuỳ chọn)")

if "_generated_password" in st.session_state:
    st.info("Đã sinh mật khẩu tự động. Copy và dán vào ô Password trước khi nhấn 'Thêm vào Vault'.")
    st.code(st.session_state._generated_password)

# Process add (simple: if fields provided)
if site and uname and (password or st.session_state.get("_generated_password")):
    pw_use = password if password else st.session_state.get("_generated_password")
    new = make_entry(site, uname, pw_use, notes or "")
    st.session_state.entries.append(new)
    token = encrypt_entries(st.session_state.key, st.session_state.entries)
    save_user_vault(st.session_state.user, st.session_state.salt, token)
    st.success(f"Đã thêm entry cho {site}. Vault được lưu.")
    if "_generated_password" in st.session_state:
        del st.session_state["_generated_password"]

# Display entries
st.subheader("Danh sách entry")
def matches_search(e, q):
    if not q:
        return True
    ql = q.lower()
    return ql in (e.get("site","").lower() + " " + e.get("username","").lower())

for e in list(st.session_state.entries):
    if not matches_search(e, search_q):
        continue
    with st.expander(f"{e['site']} — {e['username']}"):
        cols = st.columns([2,4,2])
        cols[0].write("Username")
        cols[0].write(e["username"])
        cols[1].write("Password")
        eid = e["id"]
        if st.session_state.show_pw.get(eid):
            cols[1].code(e["password"])
        else:
            cols[1].code("*" * 12)
        # Show/Hide
        if cols[2].button("Hiện/Ẩn", key=f"toggle-{eid}"):
            st.session_state.show_pw[eid] = not st.session_state.show_pw.get(eid, False)
            st.experimental_rerun()
        # Edit/Delete
        if cols[2].button("Xóa", key=f"del-{eid}"):
            st.session_state.entries = [x for x in st.session_state.entries if x["id"] != eid]
            token = encrypt_entries(st.session_state.key, st.session_state.entries)
            save_user_vault(st.session_state.user, st.session_state.salt, token)
            st.success("Đã xóa entry và lưu vault.")
            st.experimental_rerun()
        if cols[2].button("Sửa", key=f"edit-{eid}"):
            st.session_state._edit_id = eid
            st.experimental_rerun()

# Edit mode
if st.session_state.get("_edit_id"):
    edit_id = st.session_state["_edit_id"]
    item = next((x for x in st.session_state.entries if x["id"] == edit_id), None)
    if item:
        st.subheader("Sửa entry")
        new_site = st.text_input("Site", value=item["site"], key="e_site")
        new_username = st.text_input("Username", value=item["username"], key="e_user")
        new_password = st.text_input("Password", value=item["password"], key="e_pw")
        new_notes = st.text_area("Ghi chú", value=item.get("notes",""), key="e_notes")
        if st.button("Lưu thay đổi"):
            item["site"] = new_site
            item["username"] = new_username
            item["password"] = new_password
            item["notes"] = new_notes
            update_modified(item)
            token = encrypt_entries(st.session_state.key, st.session_state.entries)
            save_user_vault(st.session_state.user, st.session_state.salt, token)
            st.success("Lưu thay đổi thành công.")
            del st.session_state["_edit_id"]
            st.experimental_rerun()
        if st.button("Huỷ sửa"):
            del st.session_state["_edit_id"]
            st.experimental_rerun()
