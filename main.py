from datetime import timedelta
from dotenv import load_dotenv
import os

from flask import Flask, request, render_template, redirect, url_for, session
from flask_jwt_extended import JWTManager, create_access_token

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("APP_SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=7)

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=7)

jwt = JWTManager(app)


USERNAME = os.getenv("LOGIN_USERNAME")
PASSWORD = os.getenv("LOGIN_PASSWORD")
NAME = os.getenv("LOGIN_NAME")


@app.route("/")
def index():
    error = request.args.get("error", False)
    return render_template("login.html", error=error)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    if username == USERNAME and password == PASSWORD:
        access_token = create_access_token(identity=username)

        session["access_token"] = access_token
        session.permanent = True

        return redirect(url_for("dashboard", username=NAME))
    return redirect(url_for("index", error=True))


@app.route("/dashboard/<username>")
def dashboard(username):
    if "access_token" not in session:
        return redirect(url_for("index"))

    jwt_token = session["access_token"]
    if jwt_token:
        return render_template("dashboard.html", username=username)
    else:
        return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("access_token", None)
    return redirect(url_for("index"))

