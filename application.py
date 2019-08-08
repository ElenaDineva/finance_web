import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
# from wtforms import Form, BooleanField, StringField, PasswordField, validators

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    portfolio = db.execute(
        "SELECT symbol, SUM(shares) as number_of_shares FROM history WHERE id = :id GROUP BY symbol", id=session["user_id"])

    # we first need to put all values to 0 otherwise won't work for a new user
    value = 0
    row = 0
    company_symbol = 0
    quote = 0
    value = 0
    for row in portfolio:
        # get pricing using lookup helper
        quote = lookup(row["symbol"])["price"]
        value = int(row["number_of_shares"]) * quote
        company_symbol = lookup(row['symbol'])['name']
        rows_count = db.execute("SELECT symbol FROM portfolio WHERE id = :id AND symbol = :symbol",
        id=session["user_id"], symbol=row['symbol'])
        if len(rows_count) == 0:
            db.execute('INSERT INTO portfolio (id, symbol, name, shares, price, total) VALUES(:id, :symbol, :name, :shares, :price, :total)', id=session['user_id'],
            symbol=row['symbol'], name=company_symbol, shares=int(row["number_of_shares"]), price=quote, total=quote*int(row["number_of_shares"]))
        else:
            db.execute('UPDATE portfolio SET shares=:shares, price=:price, name=:name, total=:total WHERE id=:id AND symbol=:symbol', id=session['user_id'],
            symbol=row['symbol'], name=company_symbol, shares=int(row["number_of_shares"]), price=quote, total=quote*int(row["number_of_shares"]))

    # get user's cash from db
    cash = db.execute("SELECT cash FROM users WHERE id = :userId", userId=session["user_id"])[0]["cash"]
    net = cash

    company_shares = db.execute("SELECT * FROM portfolio WHERE id = :id", id=session["user_id"])
    shares_sum = db.execute(
        "SELECT id, SUM(total) as shares_value FROM portfolio WHERE id = :id GROUP BY id", id=session["user_id"])
    for row in shares_sum:
        shares_value = float(row['shares_value'])
        net = cash + shares_value

    # send back to index
    return render_template("index.html", company_shares=company_shares, cash=usd(cash), net=usd(net), value=usd(value), symbol=['symbol'],
    name=['name'], shares=['shares'], price=['price'], total=['total'])

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide a share symbol", 400)

        # make the entered symbol upper case and store it
        symbol = request.form.get('symbol').upper()
        # call lookup function
        quote = lookup(symbol)

        # make sure that the entered symbol is valid
        if quote == None:
            return apology("Invalid Symbol", 400)

        # Ensure the # of shares was submitted
        #number_of_shares = float(request.form.get("shares"))
        if not request.form.get("shares"):
            return apology("must provide the number of shares to buy", 400)

        # elif number_of_shares < 1:
        #    return apology("Should be at least 1", 400)

        while True:
            try:
                number_of_shares = int(request.form.get("shares"))
                assert(number_of_shares >= 1), apology("Should be at least 1", 400)
                break
            except:
                return apology("Must be a number of 1 or more!", 400)

        # Query database for username
        cash = db.execute('SELECT cash FROM users WHERE id=:id', id=session['user_id'])
        cash_available = float(cash[0]["cash"])

        # get the quote for the price of a share
        price = float(quote["price"])

        updated_cash = cash_available - price*number_of_shares

        # if the user has enough cash we proceed to bying it
        if cash_available >= price*number_of_shares:
            # Query database to update the history and users tables
            # the history update isn't WORKING!!!
            db.execute('INSERT INTO history (id, symbol, shares, price) VALUES(:id, :symbol, :number_of_shares, :price)',
            id=session['user_id'], symbol=request.form.get('symbol'), number_of_shares=number_of_shares, price=price*number_of_shares)
            db.execute('UPDATE users SET cash=:updated_cash WHERE id=:id', updated_cash=updated_cash, id=session['user_id'])
            portfolio = db.execute(
                "SELECT symbol, SUM(shares) as number_of_shares FROM history WHERE id = :id GROUP BY symbol",
                id=session["user_id"])

            flash('Shares bought!')
            return redirect("/")
        else:
            return apology('not enough cash!')
    return render_template("buy.html", methods=["POST"])


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username", "")

    names = db.execute('SELECT username FROM users WHERE username=:username', username = username)

    if len(names) >= 1 or len(username) < 1:
        return jsonify(False)
    else:
        return jsonify(True)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute('SELECT * FROM history WHERE id=:id', id=session['user_id'])
    return render_template("history.html", rows=rows, symbol=['symbol'], shares=['shares'], price=['price'], transacted=['transacted'])


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
    if request.method == "GET":
        return render_template("quote.html", methods=["POST"])
        # Ensure the symbol was submitted
        if not request.form.get("symbol"):
            return apology("Please pick a symbol", 403)
    else:
        # make the entered symbol upper case and store it
        symbol = request.form.get('symbol').upper()
        # call lookup function
        api_response = lookup(symbol)

        # make sure that the entered symbol is valid
        if api_response == None:
            return apology("Invalid Symbol")

        return render_template('quote.html', api=api_response)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password was submitted
        elif not request.form.get("confirmation"):
            return apology("Can't be blank", 400)

        # check is passowrds match
        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("Passwords don't match!", 400)

        # Query database to create the user
        rows = db.execute('INSERT INTO users (username, hash) VALUES (:username, :hash)', username=request.form.get(
            'username'), hash=generate_password_hash(request.form.get('password')))

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/login")

    # if the user reached the route via GET
    else:
        return render_template('register.html')


@app.route("/password_change", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user's password"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("old_password"):
            return apology("must provide the old password", 403)

        # Ensure password was submitted
        elif not request.form.get("new_password"):
            return apology("must provide the new password", 403)

        # Ensure password was submitted
        elif not request.form.get("confirmation"):
            return apology("Can't be blank", 403)

        # check if passowrds match
        elif request.form.get("confirmation") != request.form.get("new_password"):
            return apology("Passwords don't match!", 403)

        # Query database to check the credentials
        hashes = db.execute('SELECT hash FROM users WHERE id=:id', id=session['user_id'])
        # Ensure username exists and the password is correct
        if len(hashes) != 1 or not check_password_hash(hashes[0]["hash"], request.form.get("old_password")):
            return apology("Old password is wrong", 403)

        # updating the users hash values
        db.execute('UPDATE users SET hash = :hash WHERE id=:id',
        id=session['user_id'], hash=generate_password_hash(request.form.get('new_password')))
        flash('Password changed successfully!')
    return render_template('password_change.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide a share symbol", 403)

        # store the chosen symbol
        share_symbol = request.form.get("symbol")

        # call lookup function and get the share price
        quote = lookup(share_symbol)

        if quote == None:
            return apology("Invalid Symbol")

        price = float(quote["price"])
        company_symbol = lookup(share_symbol)['name']

        # Ensure the # of shares was submitted
        number_of_shares = float(request.form.get("shares"))
        if not request.form.get("shares"):
            return apology("must provide the number of shares to sell", 403)
        elif number_of_shares < 1:
            # return apology(tmp, 403)
            return apology("There must be at least 1", 403)

        # get the transaction history, incl. the amount of shares of symbol
        transactions = db.execute("SELECT * FROM portfolio WHERE id = :id AND symbol=:symbol",
        id=session["user_id"], symbol=request.form.get("symbol"))
        shares_owned = float(transactions[0]['shares'])

        # check to see if the user has enough stocks to sell
        if shares_owned < number_of_shares:
            return apology("insufficient stocks for transaction")
        else:
            # add a new transaction to history table
            history_update = db.execute('INSERT INTO history (id, symbol, shares, price) VALUES(:id, :symbol, :number_of_shares, :price)',
            id=session['user_id'], symbol=share_symbol, number_of_shares=-number_of_shares, price=price*number_of_shares)

            # update portfolio table
            if shares_owned == 0:
                db.execute("DELETE FROM portfolio WHERE id=:id AND symbol=:symbol",
                id=session["user_id"], symbol=stock["symbol"])
            else:
                updated_shares_owned = shares_owned - number_of_shares
                portfolio_update = db.execute('UPDATE portfolio SET shares=:shares, price=:price, name=:name, total=:total WHERE id=:id AND symbol=:symbol',
                id=session['user_id'], symbol=share_symbol, name=company_symbol, shares=updated_shares_owned, price=price, total=price*updated_shares_owned)

            # Query database for user's cash
            cash = db.execute('SELECT cash FROM users WHERE id=:id', id=session['user_id'])
            cash_available = float(cash[0]["cash"])
            updated_cash = cash_available + price*number_of_shares
            db.execute('UPDATE users SET cash=:updated_cash WHERE id=:id', updated_cash=updated_cash, id=session['user_id'])
            flash('Shares sold!')
            # return render_template('sell.html', methods=["POST"])
            return redirect("/")
    else:
        symbols = db.execute("SELECT symbol FROM portfolio WHERE id = :id", id=session["user_id"])
        stock_names = []
        for item in symbols:
            stock_names.append(item["symbol"])
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
