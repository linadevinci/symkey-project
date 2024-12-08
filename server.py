from flask import Flask, request, jsonify, send_file, redirect, session, url_for
from key_service import KeyManagementService
from password_service import PasswordManager

app = Flask(__name__)
app.secret_key = 'fbd260f4c8d7a4e90ad95371e97f1f768d650ba332ddcd1919047e874f485605'  
key_service = KeyManagementService()
password_manager = PasswordManager(key_service)

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/welcome')
def welcome():
    return send_file('welcome.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    result = password_manager.register_user(data['username'], data['password'])
    return jsonify(result)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    result = password_manager.verify_password(data['username'], data['password'])
    if result['success']:
        session['username'] = data['username']
        return jsonify({
            'success': True,
            'message': result['message'],
            'redirect': f'/welcome?username={data["username"]}'
        })
    return jsonify(result)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)