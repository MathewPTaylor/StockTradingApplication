import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT * FROM ownerships WHERE user_id = ?", session["user_id"])
    balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    sum = 0
    for stock in stocks:
        symbol = lookup(stock["symbol"])
        stock["value"] = symbol["price"]
        sum += stock["shares"] * symbol["price"]
    sum += balance[0]["cash"]
    return render_template("index.html", stocks=stocks, balance=balance[0]["cash"], sum=sum)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        shares = request.form.get("shares")
        if not shares:
            return apology("must provide shares", 400)
        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("invalid symbol", 400)
        shares = float(shares)
        if shares != int(shares) or shares <= 0:
            return apology("number of shares must be a positive integer", 400)
        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        if symbol["price"] * shares > current_cash[0]["cash"]:
            return apology("not enough money", 400)
        existing_buys = db.execute("SELECT * FROM ownerships WHERE user_id = ?", session["user_id"])
        exist = False
        for buy in existing_buys:
            if buy["symbol"] == symbol["symbol"]:
                exist = True
        if not exist:
            db.execute("INSERT INTO ownerships (user_id, symbol, shares) VALUES (?, ?, ?)", session["user_id"], symbol["symbol"], shares)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash[0]["cash"] - symbol["price"] * shares, session["user_id"])
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash[0]["cash"] - symbol["price"] * shares, session["user_id"])
            current_share = db.execute("SELECT * FROM ownerships WHERE user_id = ? AND symbol = ?", session["user_id"], symbol["symbol"])
            db.execute("UPDATE ownerships SET shares = ? WHERE user_id = ? AND symbol = ?", current_share[0]["shares"] + shares, session["user_id"], symbol["symbol"])
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transaction_datetime) VALUES (?, ?, ?, ?, ?)", session["user_id"], symbol["symbol"], shares, symbol["price"], datetime.now())
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
    return render_template("history.html", transactions = transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("invalid symbol", 400)
        return render_template("quoted.html", name=symbol["name"], symbol=symbol["symbol"], price=symbol["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation do not match", 400)
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if len(rows) >= 1:
            return apology("username already taken", 400)
        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), generate_password_hash(request.form.get("password"))
            )
        except ValueError as e:
            print(f"Value error: {e}")
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        shares = request.form.get("shares")
        if not shares:
            return apology("must provide shares", 403)
        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("invalid symbol", 403)
        shares = float(shares)
        if shares != int(shares) or shares <= 0:
            return apology("number of shares must be a positive integer", 403)
        existing_buys = db.execute("SELECT * FROM ownerships WHERE user_id = ?", session["user_id"])
        exist = False
        for buy in existing_buys:
            if buy["symbol"] == symbol["symbol"]:
                exist = True
        if not exist:
            return apology("no shares of that stock", 403)
        shares_owned = db.execute("SELECT * FROM ownerships WHERE user_id = ? AND symbol = ?", session["user_id"], symbol["symbol"])
        if int(request.form.get("shares")) > shares_owned[0]["shares"]:
            return apology("not enough shares", 403)
        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash[0]["cash"] + symbol["price"] * shares, session["user_id"])
        if int(request.form.get("shares")) == shares_owned[0]["shares"]:
            db.execute("DELETE FROM ownerships WHERE user_id = ? AND symbol = ?", session["user_id"], symbol["symbol"])
        else:
            db.execute("UPDATE ownerships SET shares = ? WHERE user_id = ? AND symbol = ?", shares_owned[0]["shares"] - shares, session["user_id"], symbol["symbol"])
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transaction_datetime) VALUES (?, ?, ?, ?, ?)", session["user_id"], symbol["symbol"], -shares, symbol["price"], datetime.now())
        return redirect("/")
    else:
        stocks = db.execute("SELECT * FROM ownerships WHERE user_id = ?", session["user_id"])
        symbol_list = []
        for stock in stocks:
            symbol_list.append(stock["symbol"])
        return render_template("sell.html", symbol_list=symbol_list)
