from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import pyotp
import qrcode
import base64
from io import BytesIO
from models import User, Product
from database import db

routes = Blueprint('routes', __name__)


@routes.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'])
    twofa_secret = pyotp.random_base32()

    new_user = User(username=data['username'], password=hashed_password, twofa_secret=twofa_secret)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', '2FA_secret': twofa_secret}), 201


@routes.route('/generate_qr/<username>', methods=['GET'])
def generate_qr(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    otp_uri = pyotp.totp.TOTP(user.twofa_secret).provisioning_uri(name=username, issuer_name="Flask2FAApp")
    img = qrcode.make(otp_uri)

    buffer = BytesIO()
    img.save(buffer, format="PNG")
    encoded_img = base64.b64encode(buffer.getvalue()).decode()

    return jsonify({'qr_code': encoded_img})


@routes.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    return jsonify({'message': 'Enter 2FA code'}), 200


@routes.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    totp = pyotp.TOTP(user.twofa_secret)
    if not totp.verify(data['code']):
        return jsonify({'message': 'Invalid 2FA code'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token})

from flask import request


#  post product
@routes.route('/product', methods=['POST'])
def add_product():
    data = request.json
    print(data)  
    
    pname = data.get("pname")
    description = data.get("description")
    price = data.get("price")
    stock = data.get("stock")

    if not isinstance(pname, str):
        return {"msg": "pname must be a string"}, 400
    if description is not None and not isinstance(description, str):
        return {"msg": "description must be a string"}, 400
    if not isinstance(price, (float, int)):  
        return {"msg": "price must be a number"}, 400
    if not isinstance(stock, int):  
        return {"msg": "stock must be an integer"}, 400

    new_product = Product(pname=pname, description=description, price=price, stock=stock)
    db.session.add(new_product)
    db.session.commit()

    return {"msg": "Product added successfully"}, 201





# get products

@routes.route('/product', methods=['GET'])

def get_products():
    products = Product.query.all()

    if not products:
        return jsonify({'message': 'No products found'}), 404

    product_list = [
        {'id': p.pid, 'pname': p.pname, 'description': p.description, 'price': p.price, 'stock': p.stock}
        for p in products
    ]

    print(product_list) 

    return jsonify({'products': product_list}), 200


# updata product
@routes.route('/product/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    product = Product.query.get(product_id)

    if not product:
        return jsonify({'message': 'Product not found'}), 404

    data = request.get_json()
    
    
    if 'pname' in data:
        product.pname = data['pname']
    if 'description' in data:
        product.description = data['description']
    if 'price' in data:
        product.price = data['price']
    if 'stock' in data:
        product.stock = data['stock']

    
    db.session.commit()

    return jsonify({
        'message': 'Product updated successfully',
        'product': {
            'id': product.pid,
            'pname': product.pname,
            'description': product.description,
            'price': product.price,
            'stock': product.stock
        }
    }), 200


   

@routes.route('/product/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    product = Product.query.get(product_id)

    if not product:
        return jsonify({'message': 'Product not found'}), 404

    db.session.delete(product)
    db.session.commit()

    return jsonify({'message': 'Product deleted successfully'}), 200




