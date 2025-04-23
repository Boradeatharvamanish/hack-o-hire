from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO
from utils.log_utils import generate_log, save_log
from utils.anomaly_predictor import start_monitoring_in_thread

app = Flask(__name__)
app.secret_key = 'demo-secret'
socketio = SocketIO(app)  # 👈 Real-time update enabled

PRODUCTS = [
    {"id": 1, "name": "Laptop", "price": 50000},
    {"id": 2, "name": "Phone", "price": 15000},
    {"id": 3, "name": "Headphones", "price": 3000}
]

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        session["username"] = username
        session["cart"] = []

        req_info = {"body": {"username": username}}
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

    req_info = {
        "body": {"user": username},
        "correlation_id": session.get("correlation_id"),
        "session_id": session.get("session_id"),
        "user_id": session.get("user_id")
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

    req_info = {
        "body": {"product_id": product_id},
        "correlation_id": session.get("correlation_id"),
        "session_id": session.get("session_id"),
        "user_id": session.get("user_id")
    }
    log, _, _, _ = generate_log("cart", req_info, previous_api="catalog")
    save_log(log, "cart")

    return redirect("/catalog")

@app.route('/payment')
def payment():
    cart_ids = session.get("cart", [])
    cart_items = [p for p in PRODUCTS if p["id"] in cart_ids]
    total = sum(p["price"] for p in cart_items)

    req_info = {
        "body": {"cart_id": "mock-cart"},
        "correlation_id": session.get("correlation_id"),
        "session_id": session.get("session_id"),
        "user_id": session.get("user_id")
    }
    log, _, _, _ = generate_log("payment", req_info, previous_api="cart")
    save_log(log, "payment")

    return render_template("payment.html", cart=cart_items, total=total)

@app.route('/make_payment', methods=["POST"])
def make_payment():
    req_info = {
        "body": {"cart_id": "mock-cart"},
        "correlation_id": session.get("correlation_id"),
        "session_id": session.get("session_id"),
        "user_id": session.get("user_id")
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
    return render_template("dashboard.html")  # Realtime anomaly dashboard

if __name__ == '__main__':
    # Start anomaly detection thread with access to socketio
    start_monitoring_in_thread(socketio)  # 👈 Pass socketio for real-time broadcasting
    socketio.run(app, debug=True)  # 👈 Run with socketio
