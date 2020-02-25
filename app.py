import hashlib
import time
import requests
import functools
from flask import Flask, session, render_template, redirect, request, abort, jsonify

app = Flask(__name__, template_folder='static')

app.secret_key = 'aiuYbK/Beob0/ABOKlO0p6Rn89xAMQWlFJSAWHV9hYc='


def login_ok():
    return session.get('username') and session.get('access_token')


def check_login(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not login_ok():
            return redirect("/login")
        return func(*args, **kwargs)
    return wrapper


@app.route('/login', methods=['GET', 'POST'])
def login():
    if login_ok():
        return redirect('/')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template("login.html", error="请输入用户名或密码")
        resp = requests.get(f"http://www.svpypark.com/clientUser/mobile/login.do?userName={username}&password={password}")
        if resp.status_code != 200:
            return abort(resp.status_code)
        result = resp.json()
        if int(result["app_result_key"]) == 0 and result["access_token"]:
            session['username'] = username
            session['access_token'] = result['access_token']
            return redirect('/')
        else:
            return render_template("login.html", error=result.get("app_result_message_key", "未知错误"))
    else:
        return render_template("login.html")


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect('/')


def get_auth_parameters(token):
    st = int(time.time() * 1000)
    return {"access_token": token, "st": st, "signature": hashlib.md5(("smartiABC" + str(st) + token).encode("utf8")).hexdigest()}


@app.route('/', methods=['GET'])
@check_login
def index():
    resp = requests.post("http://www.svpypark.com/entrance/getRoomList.do", data={"pageNo": 1, "pageSize": 10, **get_auth_parameters(session["access_token"])})
    if resp.status_code != 200:
        return abort(resp.status_code)
    result = resp.json()
    if int(result["app_result_key"]) == 0:
        return render_template("index.html", doors=result.get("list", []), username=session["username"])
    return abort(500)


@check_login
@app.route('/open/<door_id>', methods=['GET'])
def open_door(door_id):
    resp = requests.post('http://www.svpypark.com/entrance/openDoor.do', data={"id": door_id, ** get_auth_parameters(session["access_token"])})
    if resp.status_code != 200:
        return abort(resp.status_code)
    result = resp.json()
    system_result_key = int(result["system_result_key"])
    app_result_key = int(result["app_result_key"])
    if system_result_key == 0 and app_result_key == 0:
        return jsonify({"code": 0, "msg": "开门成功"})
    elif system_result_key == 7:
        return jsonify({"code": 7, "msg": "系统错误"})
    else:
        return jsonify({"code": system_result_key, "msg": result.get("app_result_message_key", "未知错误")})


if __name__ == '__main__':
    app.run()
