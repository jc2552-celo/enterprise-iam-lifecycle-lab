import os
import json
from datetime import datetime, timezone

import httpx
from dotenv import load_dotenv

load_dotenv()

SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
REALM = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_ADMIN_CLIENT_ID")
CLIENT_SECRET = os.getenv("KEYCLOAK_ADMIN_CLIENT_SECRET")

AUDIT_DIR = "audit"
AUDIT_FILE = os.path.join(AUDIT_DIR, "lifecycle_audit.jsonl")


def write_audit_event(action, username, details):
    os.makedirs(AUDIT_DIR, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "username": username,
        "details": details,
    }

    with open(AUDIT_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def get_admin_token():
    token_url = (
        f"{SERVER_URL}/realms/{REALM}/protocol/openid-connect/token"
    )

    response = httpx.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        timeout=10.0,
    )

    response.raise_for_status()

    return response.json()["access_token"]


def get_headers():
    token = get_admin_token()

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def find_user(username):
    url = f"{SERVER_URL}/admin/realms/{REALM}/users"

    response = httpx.get(
        url,
        headers=get_headers(),
        params={
            "username": username,
            "exact": "true",
        },
        timeout=10.0,
    )

    response.raise_for_status()

    users = response.json()

    if not users:
        return None

    return users[0]


def create_user(
    username,
    email,
    first_name,
    last_name,
    password,
):
    existing_user = find_user(username)

    if existing_user:
        return {
            "status": "exists",
            "username": username,
            "user_id": existing_user["id"],
        }

    url = f"{SERVER_URL}/admin/realms/{REALM}/users"

    payload = {
        "username": username,
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "enabled": True,
        "emailVerified": False,
        "credentials": [
            {
                "type": "password",
                "value": password,
                "temporary": False,
            }
        ],
    }

    response = httpx.post(
        url,
        json=payload,
        headers=get_headers(),
        timeout=10.0,
    )

    if response.status_code != 201:
        return {
            "status": "error",
            "status_code": response.status_code,
            "response": response.text,
        }

    user = find_user(username)

    return {
        "status": "created",
        "username": username,
        "user_id": user["id"],
    }


def find_group(group_name):
    url = f"{SERVER_URL}/admin/realms/{REALM}/groups"

    response = httpx.get(
        url,
        headers=get_headers(),
        params={
            "search": group_name,
        },
        timeout=10.0,
    )

    response.raise_for_status()

    groups = response.json()

    for group in groups:
        if group["name"].lower() == group_name.lower():
            return group

    return None


def assign_group(user_id, group_name):
    group = find_group(group_name)

    if not group:
        return {
            "status": "error",
            "message": f"Group '{group_name}' not found",
        }

    url = (
        f"{SERVER_URL}/admin/realms/{REALM}"
        f"/users/{user_id}/groups/{group['id']}"
    )

    response = httpx.put(
        url,
        headers=get_headers(),
        timeout=10.0,
    )

    if response.status_code == 204:
        return {
            "status": "assigned",
            "group": group["name"],
        }

    return {
        "status": "error",
        "status_code": response.status_code,
        "response": response.text,
    }


def remove_group(user_id, group_name):
    group = find_group(group_name)

    if not group:
        return {
            "status": "error",
            "message": f"Group '{group_name}' not found",
        }

    url = (
        f"{SERVER_URL}/admin/realms/{REALM}"
        f"/users/{user_id}/groups/{group['id']}"
    )

    response = httpx.delete(
        url,
        headers=get_headers(),
        timeout=10.0,
    )

    if response.status_code == 204:
        return {
            "status": "removed",
            "group": group["name"],
        }

    return {
        "status": "error",
        "status_code": response.status_code,
        "response": response.text,
    }


def find_realm_role(role_name):
    url = f"{SERVER_URL}/admin/realms/{REALM}/roles"

    response = httpx.get(
        url,
        headers=get_headers(),
        timeout=10.0,
    )

    response.raise_for_status()

    roles = response.json()

    for role in roles:
        if role["name"].lower() == role_name.lower():
            return role

    return None


def assign_realm_role(user_id, role_name):
    role = find_realm_role(role_name)

    if not role:
        return {
            "status": "error",
            "message": f"Role '{role_name}' not found",
        }

    url = (
        f"{SERVER_URL}/admin/realms/{REALM}"
        f"/users/{user_id}/role-mappings/realm"
    )

    response = httpx.post(
        url,
        headers=get_headers(),
        json=[
            {
                "id": role["id"],
                "name": role["name"],
            }
        ],
        timeout=10.0,
    )

    if response.status_code == 204:
        return {
            "status": "assigned",
            "role": role["name"],
        }

    return {
        "status": "error",
        "status_code": response.status_code,
        "response": response.text,
    }


def remove_realm_role(user_id, role_name):
    role = find_realm_role(role_name)

    if not role:
        return {
            "status": "not_found",
            "role": role_name,
        }

    url = (
        f"{SERVER_URL}/admin/realms/{REALM}"
        f"/users/{user_id}/role-mappings/realm"
    )

    response = httpx.request(
        "DELETE",
        url,
        headers=get_headers(),
        json=[
            {
                "id": role["id"],
                "name": role["name"],
            }
        ],
        timeout=10.0,
    )

    if response.status_code == 204:
        return {
            "status": "removed",
            "role": role["name"],
        }

    return {
        "status": "error",
        "status_code": response.status_code,
        "response": response.text,
    }


def disable_user(username):
    user = find_user(username)

    if not user:
        return {
            "status": "error",
            "message": f"User '{username}' not found",
        }

    user["enabled"] = False

    url = (
        f"{SERVER_URL}/admin/realms/{REALM}"
        f"/users/{user['id']}"
    )

    response = httpx.put(
        url,
        headers=get_headers(),
        json=user,
        timeout=10.0,
    )

    if response.status_code == 204:
        return {
            "status": "disabled",
            "username": username,
        }

    return {
        "status": "error",
        "status_code": response.status_code,
        "response": response.text,
    }


def logout_user_sessions(user_id):
    url = (
        f"{SERVER_URL}/admin/realms/{REALM}"
        f"/users/{user_id}/logout"
    )

    response = httpx.post(
        url,
        headers=get_headers(),
        timeout=10.0,
    )

    if response.status_code == 204:
        return {
            "status": "sessions_terminated",
        }

    return {
        "status": "error",
        "status_code": response.status_code,
        "response": response.text,
    }


def onboard_user(
    username,
    email,
    first_name,
    last_name,
    password,
    group_name,
    role_name,
):
    user_result = create_user(
        username,
        email,
        first_name,
        last_name,
        password,
    )

    if user_result["status"] == "error":
        return user_result

    user_id = user_result["user_id"]

    group_result = assign_group(
        user_id,
        group_name,
    )

    role_result = assign_realm_role(
        user_id,
        role_name,
    )

    result = {
        "username": username,
        "user_status": user_result["status"],
        "group": group_result,
        "role": role_result,
    }

    write_audit_event(
        "ONBOARD_USER",
        username,
        result,
    )

    return result


def transfer_user(
    username,
    old_group,
    new_group,
):
    user = find_user(username)

    if not user:
        return {
            "status": "error",
            "message": f"User '{username}' not found",
        }

    remove_result = remove_group(
        user["id"],
        old_group,
    )

    assign_result = assign_group(
        user["id"],
        new_group,
    )

    result = {
        "username": username,
        "old_group": remove_result,
        "new_group": assign_result,
    }

    write_audit_event(
        "TRANSFER_USER",
        username,
        result,
    )

    return result


def promote_user(
    username,
    new_role,
):
    user = find_user(username)

    if not user:
        return {
            "status": "error",
            "message": f"User '{username}' not found",
        }

    role_result = assign_realm_role(
        user["id"],
        new_role,
    )

    result = {
        "username": username,
        "role": role_result,
    }

    write_audit_event(
        "PROMOTE_USER",
        username,
        result,
    )

    return result


def offboard_user(username):
    user = find_user(username)

    if not user:
        return {
            "status": "error",
            "message": f"User '{username}' not found",
        }

    user_id = user["id"]

    manager_result = remove_realm_role(
        user_id,
        "manager",
    )

    admin_result = remove_realm_role(
        user_id,
        "admin",
    )

    session_result = logout_user_sessions(
        user_id
    )

    disable_result = disable_user(
        username
    )

    result = {
        "username": username,
        "manager_role": manager_result,
        "admin_role": admin_result,
        "sessions": session_result,
        "account": disable_result,
    }

    write_audit_event(
        "OFFBOARD_USER",
        username,
        result,
    )

    return result
