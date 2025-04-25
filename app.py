from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO
from utils.log_utils import generate_log, save_log
from utils.anomaly_predictor import start_monitoring_in_thread
import random

app = Flask(__name__)
app.secret_key = 'demo-secret'
socketio = SocketIO(app)

PRODUCTS = [
    {"id": 1, "name": "Laptop", "price": 50000},
    {"id": 2, "name": "Phone", "price": 15000},
    {"id": 3, "name": "Headphones", "price": 3000}
]

def get_dynamic_server_info():
    """Randomly decide whether to use same server or a new one."""
    if "server_id" not in session or random.random() < 0.3:  # 30% chance to change server
        session["server_id"] = f"server_{random.randint(1, 5)}"
        session["instance_id"] = f"instance_{random.choice(['a', 'b', 'c'])}{random.randint(1, 3)}"
    return session["server_id"], session["instance_id"]

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        session["username"] = username
        session["cart"] = []

        server_id, instance_id = get_dynamic_server_info()

        req_info = {
            "body": {"username": username},
            "server_id": server_id,
            "instance_id": instance_id
        }

        log, corr_id, session_id, user_id = generate_log("auth", req_info)
        session["correlation_id"] = corr_id
        session["session_id"] = session_id
        session["user_id"] = user_id

        save_log(log, "auth")
        return redirect("/catalog")

    return render_template("login.html")

@app.route('/catalog')
def catalog():
    username = session.get("username")
    cart_ids = session.get("cart", [])
    cart_items = [p for p in PRODUCTS if p["id"] in cart_ids]

    server_id, instance_id = get_dynamic_server_info()

    req_info = {
        "body": {"user": username},
        "correlation_id": session.get("correlation_id"),
        "session_id": session.get("session_id"),
        "user_id": session.get("user_id"),
        "server_id": server_id,
        "instance_id": instance_id
    }

    log, _, _, _ = generate_log("catalog", req_info, previous_api="auth")
    save_log(log, "catalog")

    return render_template("catalog.html", products=PRODUCTS, cart=cart_items, username=username)

@app.route('/add_to_cart/<int:product_id>', methods=["GET"])
def add_to_cart(product_id):
    cart = session.get("cart", [])
    if product_id not in cart:
        cart.append(product_id)
        session["cart"] = cart

    server_id, instance_id = get_dynamic_server_info()

    req_info = {
        "body": {"product_id": product_id},
        "correlation_id": session.get("correlation_id"),
        "session_id": session.get("session_id"),
        "user_id": session.get("user_id"),
        "server_id": server_id,
        "instance_id": instance_id
    }

    log, _, _, _ = generate_log("cart", req_info, previous_api="catalog")
    save_log(log, "cart")

    return redirect("/catalog")

@app.route('/payment')
def payment():
    cart_ids = session.get("cart", [])
    cart_items = [p for p in PRODUCTS if p["id"] in cart_ids]
    total = sum(p["price"] for p in cart_items)

    server_id, instance_id = get_dynamic_server_info()

    req_info = {
        "body": {"cart_id": "mock-cart"},
        "correlation_id": session.get("correlation_id"),
        "session_id": session.get("session_id"),
        "user_id": session.get("user_id"),
        "server_id": server_id,
        "instance_id": instance_id
    }

    log, _, _, _ = generate_log("payment", req_info, previous_api="cart")
    save_log(log, "payment")

    return render_template("payment.html", cart=cart_items, total=total)

@app.route('/make_payment', methods=["POST"])
def make_payment():
    server_id, instance_id = get_dynamic_server_info()

    req_info = {
        "body": {"cart_id": "mock-cart"},
        "correlation_id": session.get("correlation_id"),
        "session_id": session.get("session_id"),
        "user_id": session.get("user_id"),
        "server_id": server_id,
        "instance_id": instance_id
    }

    log, _, _, _ = generate_log("make_payment", req_info, previous_api="payment")
    save_log(log, "make_payment")

    session["cart"] = []
    return redirect("/thankyou")

@app.route('/thankyou')
def thankyou():
    return render_template("thankyou.html")

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

if __name__ == '__main__':
    start_monitoring_in_thread(socketio)
    socketio.run(app, debug=True)