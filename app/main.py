import os

import jwt
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

app = FastAPI(title="Enterprise IAM Lifecycle Lab")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "dev-secret"),
)

realm = os.getenv("KEYCLOAK_REALM")
server_url = os.getenv("KEYCLOAK_SERVER_URL")
client_id = os.getenv("KEYCLOAK_CLIENT_ID")

oauth = OAuth()

oauth.register(
    name="keycloak",
    client_id=client_id,
    client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET"),
    server_metadata_url=(
        f"{server_url}/realms/{realm}/"
        ".well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid profile email"
    },
)


def get_roles_from_token(access_token: str):
    jwks_url = (
        f"{server_url}/realms/{realm}/"
        "protocol/openid-connect/certs"
    )

    jwks_client = jwt.PyJWKClient(jwks_url)

    signing_key = jwks_client.get_signing_key_from_jwt(
        access_token
    )

    payload = jwt.decode(
        access_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=client_id,
        options={"verify_aud": False},
    )

    roles = payload.get(
        "realm_access",
        {}
    ).get(
        "roles",
        []
    )

    return [
        role.lower()
        for role in roles
    ]


def has_role(
    request: Request,
    role: str
):
    user = request.session.get("user")

    if not user:
        return False

    user_roles = user.get(
        "roles",
        []
    )

    return role.lower() in user_roles


@app.get(
    "/",
    response_class=HTMLResponse
)
async def home(
    request: Request
):
    user = request.session.get("user")

    if not user:
        return """
        <h1>Enterprise IAM Lifecycle Lab</h1>

        <p>You are not logged in.</p>

        <a href="/login">
            Login with Keycloak
        </a>
        """

    roles = ", ".join(
        user.get(
            "roles",
            []
        )
    )

    username = user.get(
        "preferred_username",
        "Unknown"
    )

    email = user.get(
        "email",
        "Not available"
    )

    return f"""
    <h1>Enterprise IAM Lifecycle Lab</h1>

    <p>
        <strong>User:</strong>
        {username}
    </p>

    <p>
        <strong>Email:</strong>
        {email}
    </p>

    <p>
        <strong>Roles:</strong>
        {roles}
    </p>

    <hr>

    <p>
        <a href="/employee">
            Employee Area
        </a>
    </p>

    <p>
        <a href="/manager">
            Manager Area
        </a>
    </p>

    <p>
        <a href="/admin">
            Admin Area
        </a>
    </p>

    <hr>

    <a href="/logout">
        Logout
    </a>
    """


@app.get("/login")
async def login(
    request: Request
):
    redirect_uri = (
        f"{os.getenv('APP_BASE_URL')}"
        "/callback"
    )

    return await oauth.keycloak.authorize_redirect(
        request,
        redirect_uri
    )


@app.get("/callback")
async def callback(
    request: Request
):
    token = (
        await oauth.keycloak.authorize_access_token(
            request
        )
    )

    user = token.get("userinfo")

    if user is None:
        user = await oauth.keycloak.userinfo(
            token=token
        )

    roles = get_roles_from_token(
        token["access_token"]
    )

    session_user = dict(user)

    session_user["roles"] = roles

    request.session["user"] = session_user

    return RedirectResponse(
        url="/"
    )


@app.get(
    "/employee",
    response_class=HTMLResponse
)
async def employee_area(
    request: Request
):
    if not has_role(
        request,
        "employee"
    ):
        return HTMLResponse(
            """
            <h1>403 - Employee access required</h1>

            <a href="/">
                Return home
            </a>
            """,
            status_code=403
        )

    return """
    <h1>Employee Area</h1>

    <p>
        Access granted.
    </p>

    <a href="/">
        Return home
    </a>
    """


@app.get(
    "/manager",
    response_class=HTMLResponse
)
async def manager_area(
    request: Request
):
    if not has_role(
        request,
        "manager"
    ):
        return HTMLResponse(
            """
            <h1>403 - Manager access required</h1>

            <a href="/">
                Return home
            </a>
            """,
            status_code=403
        )

    return """
    <h1>Manager Area</h1>

    <p>
        Manager authorization successful.
    </p>

    <a href="/">
        Return home
    </a>
    """


@app.get(
    "/admin",
    response_class=HTMLResponse
)
async def admin_area(
    request: Request
):
    if not has_role(
        request,
        "admin"
    ):
        return HTMLResponse(
            """
            <h1>403 - Administrator access required</h1>

            <a href="/">
                Return home
            </a>
            """,
            status_code=403
        )

    return """
    <h1>Administrator Area</h1>

    <p>
        Privileged access granted.
    </p>

    <a href="/">
        Return home
    </a>
    """


@app.get("/logout")
async def logout(
    request: Request
):
    request.session.clear()

    post_logout_redirect_uri = (
        f"{os.getenv('APP_BASE_URL')}/"
    )

    logout_url = (
        f"{server_url}/realms/{realm}/"
        "protocol/openid-connect/logout"
        f"?post_logout_redirect_uri={post_logout_redirect_uri}"
        f"&client_id={client_id}"
    )

    return RedirectResponse(
        url=logout_url
    )
