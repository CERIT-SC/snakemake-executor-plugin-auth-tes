import requests
import jwt
import urllib.parse as urlparse

GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"


class AuthClient:
    def __init__(self, client_id, client_secret, oidc_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.oidc_url = oidc_url if not oidc_url.endswith("/") else oidc_url[:-1]

        self.introspect_url = self.oidc_url + "/introspect"
        self.token_url = self.oidc_url + "/token"
        self.register_url = self.oidc_url + "/register"
        self.jwks_url = self.oidc_url + "/jwk"

        self.basic_auth = requests.auth.HTTPBasicAuth(
            self.client_id, self.client_secret
        )

    def is_token_expired(self, token):
        jwks_client = jwt.PyJWKClient(self.jwks_url)
        header = jwt.get_unverified_header(token)
        key = jwks_client.get_signing_key(header["kid"]).key

        try:
            jwt.decode(token, key, [header["alg"]], options={"verify_aud": False})
        except jwt.ExpiredSignatureError:
            return True

        return False

    def is_token_valid(self, token):
        body = {"token": token}

        response = requests.post(self.introspect_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to validate the access token: " + response.text)

        token_info = response.json()

        if token_info["active"]:
            return True

        return False

    def get_new_token(self, scopes, audience=None):
        body = {
            "grant_type": GRANT_TYPE_CLIENT_CREDENTIALS,
            "scope": " ".join(scopes),
        }

        if audience:
            body["audience"] = audience

        response = requests.post(self.token_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to get a new access token: " + response.text)

        return response.json()

    def exchange_access_token(self, token, scopes, audience=None):
        body = {
            "subject_token": token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": " ".join(scopes),
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        }

        if audience:
            body["audience"] = audience

        response = requests.post(self.token_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to exchange access token: " + response.text)

        return response.json()

    def refresh_access_token(self, refresh_token):
        body = {"refresh_token": refresh_token, "grant_type": "refresh_token" ""}

        response = requests.post(self.token_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to refresh access token: " + response.text)

        return response.json()

    def register_client(
        self,
        client_name,
        resource_ids,
        scopes,
        access_token_validity_seconds=600,
        refresh_token_validity_seconds=3600,
    ):
        new_token_response = self.get_new_token(["client_dynamic_registration"])
        access_token = new_token_response["access_token"]

        body = {
            "client_name": client_name,
            "grant_types": [
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "refresh_token",
                "client_credentials",
            ],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": scopes,
            "resources": resource_ids,
            "access_token_validity_seconds": access_token_validity_seconds,
            "refresh_token_validity_seconds": refresh_token_validity_seconds,
        }

        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.post(self.register_url, json=body, headers=headers)

        if response.status_code != 201:
            raise Exception("Failed to register a new client: " + response.text)

        response_data = response.json()

        return {
            "client_id": response_data["client_id"],
            "client_secret": response_data["client_secret"],
        }

    def deregister_self(self):
        new_token_response = self.get_new_token(["client_dynamic_deregistration"])
        access_token = new_token_response["access_token"]

        headers = {"Authorization": f"Bearer {access_token}"}
        base_register_url = (
            self.register_url
            if self.register_url.endswith("/")
            else self.register_url + "/"
        )
        url = urlparse.urljoin(base_register_url, self.client_id)
        response = requests.delete(url, headers=headers)

        if response.status_code != 204:
            raise Exception("Failed to deregister the client: " + response.text)
