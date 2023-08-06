from flask import Flask, request, jsonify
import random

app = Flask(__name__)

# Initialize the canvas with white pixels
canvas = [{'id': i, 'color': 'white'} for i in range(1, 10001)]

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/occupy', methods=['POST'])
def occupy_pixel():
    pixel_id = int(request.args.get('pixel'))
    
    # Check if the pixel is already occupied
    if canvas[pixel_id - 1]['color'] != 'white':
        return jsonify({'message': 'Pixel already occupied'})

    # Update pixel color
    color = '#{:06x}'.format(random.randint(0, 0xFFFFFF))
    canvas[pixel_id - 1]['color'] = color
    
    return jsonify({'message': 'Pixel occupied', 'color': color})

if __name__ == '__main__':
    app.run()

# 在已有的后端代码中添加以下内容

# 用户信息示例，实际应用中需要存储在数据库中
users = {'user1': 'password1', 'user2': 'password2'}

@app.route('/login')
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    if username in users and users[username] == password:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False})

# 在已有的后端代码中添加以下内容
from Crypto.Cipher import AES
import base64

# 加密解密函数
def encrypt(data):
    cipher = AES.new(secret_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')

def decrypt(data):
    data = base64.b64decode(data.encode('utf-8'))
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(secret_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.decode('utf-8')

# 用户信息示例，实际应用中需要存储在数据库中
users = {'user1': 'password1', 'user2': 'password2'}

@app.route('/login')
def login():
    encrypted_username = request.args.get('username')
    encrypted_password = request.args.get('password')
    username = decrypt(encrypted_username)
    password = decrypt(encrypted_password)

    if username in users and users[username] == password:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False})
