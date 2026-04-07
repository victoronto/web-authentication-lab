```bash
(venv) vma@300-31272-MAC python % python app.py
Traceback (most recent call last):
  File "/Users/vma/Documents/temp/web-authentication-lab/01-basic-auth/python/app.py", line 14, in <module>
    "admin": generate_password_hash("secret123"),
  File "/Users/vma/Documents/temp/web-authentication-lab/01-basic-auth/python/venv/lib/python3.9/site-packages/werkzeug/security.py", line 119, in generate_password_hash
    h, actual_method = _hash_internal(method, salt, password)
  File "/Users/vma/Documents/temp/web-authentication-lab/01-basic-auth/python/venv/lib/python3.9/site-packages/werkzeug/security.py", line 54, in _hash_internal
    hashlib.scrypt(
AttributeError: module 'hashlib' has no attribute 'scrypt'
(venv) vma@300-31272-MAC python % (venv) vma@300-31272-MAC python % python app.py
Traceback (most recent call last):
  File "/Users/vma/Documents/temp/web-authentication-lab/01-basic-auth/python/app.py", line 14, in <module>
    "admin": generate_password_hash("secret123"),
  File "/Users/vma/Documents/temp/web-authentication-lab/01-basic-auth/python/venv/lib/python3.9/site-packages/werkzeug/security.py", line 119, in generate_password_hash
    h, actual_method = _hash_internal(method, salt, password)
  File "/Users/vma/Documents/temp/web-authentication-lab/01-basic-auth/python/venv/lib/python3.9/site-packages/werkzeug/security.py", line 54, in _hash_internal
    hashlib.scrypt(
AttributeError: module 'hashlib' has no attribute 'scrypt'
(venv) vma@300-31272-MAC python % python --version
Python 3.9.6
```
MacBook 上装的是 Python 3.9，而新版 Werkzeug（Flask 的底层依赖）默认使用 scrypt 算法做密码哈希。问题是 macOS 自带的 Python 3.9 在编译时没有启用 OpenSSL 的 scrypt 支持，所以 hashlib.scrypt 不存在。
Module 01 的文档里提到过 Werkzeug 2.3+ 默认从 pbkdf2:sha256 切换到了 scrypt——你正好踩到了这个兼容性问题。

```bash
% which -a python3
/Users/vma/.pyenv/shims/python3
/usr/bin/python3
```
第一条路径 /Users/vma/.pyenv/shims/python3 说明你装了 pyenv。Shims 是 pyenv 的代理机制——所有 python3 调用都先经过 pyenv，由它决定实际使用哪个版本。
```bash
vma@300-31272-MAC 01-basic-auth % pyenv versions
* system (set by /Users/vma/.pyenv/version)
  3.13.9
vma@300-31272-MAC 01-basic-auth % pyenv version 
system (set by /Users/vma/.pyenv/version)
```
只在这个项目目录设置（推荐）
```bash
pyenv local 3.13.9
# 这会在当前目录创建一个 .python-version 文件
# 以后每次 cd 进这个目录，pyenv 自动切换到这个版本
cat .python-version
3.13.9

# 确认
% python3 --version
Python 3.13.9


# 重建 venv
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install Flask Flask-HTTPAuth
```