import logging
from flask import Flask, request, redirect, flash, url_for
from flask import session, make_response, g
from flask import current_app

from forms import RegistrationForm, LoginForm
from keycloak_utils import get_admin, create_user, get_oidc, get_token, check_token


logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config.from_object("settings")


@app.before_request
def load_user():
    g.username = session.get("username")
    g.access_token = session.get("access_token")


@app.route("/")
def home():
    return "HOME"


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        oidc_obj = get_oidc()
        token = get_token(oidc_obj, form.username.data, form.password.data)
        print("\nTOKEN: %s\n" % token)
        response = make_response(redirect(url_for("home")))
        if token:
            response.set_cookie("access_token", token["access_token"])
            session["access_token"] = token["access_token"]
            session["username"] = form.username.data
        return response
    return "LOGIN FAILED"


@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("access_token", None)
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm(request.form)
    if request.method == "POST" and form.validate():
        admin = get_admin()
        create_user(admin, form.username.data, form.email.data, form.password.data)
        flash("Thanks for registering")
        return "Registration successful"
    return "Registration failed"


@app.route("/headers")
def headers():
    return dict(request.headers)


@app.route("/protected")
def protected():
    resp = "Forbidden!"
    access_token = session.get("access_token")
    if access_token:
        if check_token(access_token):
            headers = {"Authorization": "Bearer " + access_token}
            resp = "Protected resource is accessible. Yay! Here is the response: Hello"
    return resp


@app.route("/rbac")
def rbac():
    resp = "Forbidden!"
    access_token = session.get("access_token")
    oidc_obj = get_oidc()
    oidc_obj.load_authorization_config("test-authz-config.json")
    policies = oidc_obj.get_policies(access_token)
    print("\nPOLICIES: %s\n" % policies)
    permissions = oidc_obj.get_permissions(access_token, method_token_info="introspect")
    print("\nPERMISSIONS: %s\n" % permissions)
    resourrceBasedPermissions = oidc_obj.uma_permissions(
        access_token, "Protected-Resource"
    )  # check permissions for specific resource
    print("\nRESOURCE BASED PERMISSIONS: %s\n" % resourrceBasedPermissions)
    if resourrceBasedPermissions:
        resp = "You have permissions to access this resource."
        return resp
    return "Forbidden!"
