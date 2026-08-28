import requests
import time
import json
import os


class TokenManager:
    def __init__(self, username, password, client_id="clearml-apis", store_path="token_stored.json"):
        self.username = username
        self.password = password
        self.client_id = client_id
        self.token = None
        self.token_expiry = 0
        self.refresh_token = None
        self.store_path = store_path
        print(f"[INIT] - Initializing TokenManager for user: '{self.username}'")
        self.load_token_data()

    def get_token(self):
        print("[GET_TOKEN] - Checking Access Token...")
        # Se il token esiste ed è valido, lo riuso
        if self.token and time.time() < self.token_expiry:
            print("[GET_TOKEN] - Access Token found and valid.")
            return self.token

        print("[GET_TOKEN] - Access Token not found or expired.")
        if self.refresh_token:
            print("[GET_TOKEN] - Trying with Refresh Token...")
            token_data = self.get_token_via_refresh_token(self.refresh_token)
            if token_data and 'access_token' in token_data:
                print("[GET_TOKEN] - Access Token successfully retrieved with Refresh Token.")
                self.save_token_data(token_data)
                return self.token
            else:
                print("[GET_TOKEN] - Request with Refresh token failed. Trying request with username and password.")

        print("[GET_TOKEN] - Requesting Access Token with username and password...")
        token_data = self.get_token_via_user_credentials(self.username, self.password)
        if token_data and 'access_token' in token_data:
            print("[GET_TOKEN] - Access token successfully retrieved with username and password.")
            self.save_token_data(token_data)
            return self.token

        print("[GET_TOKEN] - ERROR: Can't get a valid Access Token.")
        raise Exception("Unable to get a valid token")

    def get_token_via_user_credentials(self, username, password):
        print("[GET_TOKEN_VIA_USER_CREDENTIALS] - Requesting Access Token with username and password...")
        payload = {
            'f': 'json',
            'client_id': self.client_id,
            'grant_type': 'password',
            'username': username,
            'password': password
        }
        header = {'Content-Type': 'application/x-www-form-urlencoded'}
        url_token = "https://www.snap4city.org/auth/realms/master/protocol/openid-connect/token"
        response = requests.post(url_token, data=payload, headers=header)
        print(f"[GET_TOKEN_VIA_USER_CREDENTIALS] - Response status code: {response.status_code}")
        return response.json()

    def get_token_via_refresh_token(self, refresh_token):
        print("[GET_TOKEN_VIA_REFRESH_TOKEN] - Sending request with Refresh Token...")
        payload = {
            'f': 'json',
            'client_id': self.client_id,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }
        header = {'Content-Type': 'application/x-www-form-urlencoded'}
        url_token = ("https://www.snap4city.org/auth/realms/master/protocol/openid-connect/token"
                     "")
        response = requests.post(url_token, data=payload, headers=header)
        print(f"[GET_TOKEN_VIA_REFRESH_TOKEN] - Status code response: {response.status_code}")
        return response.json()

    def save_token_data(self, token_data):
        print("[SAVE_TOKEN] - Saving Access Token on JSON file...")
        self.token = token_data['access_token']
        self.refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in', 3600)
        self.token_expiry = time.time() + expires_in - 60

        data = {
            "access_token": self.token,
            "refresh_token": self.refresh_token,
            "token_expiry": self.token_expiry
        }
        try:
            with open(self.store_path, "w") as f:
                json.dump(data, f)
            print("[SAVE_TOKEN] - Access Token successfully saved.")
        except Exception as e:
            print(f"[SAVE_TOKEN] - ERROR in saving Access Token: {e}")

    def load_token_data(self):
        if os.path.exists(self.store_path):
            print(f"[LOAD_TOKEN] - Loading Access Token from JSON file '{self.store_path}' (if present)...")
            try:
                with open(self.store_path, "r") as f:
                    data = json.load(f)
                self.token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
                self.token_expiry = data.get("token_expiry", 0)
                print(f"[LOAD_TOKEN] - Access Token successfully loaded from stored JSON, still valid")
            except Exception as e:
                print(f"[LOAD_TOKEN] - ERROR in loading Access Token: {e}")
                self.token = None
                self.refresh_token = None
                self.token_expiry = 0
        else:
            print(f"[LOAD] - No JSON file with Saved Access Token found in ('{self.store_path}').")
            self.token = None
            self.refresh_token = None
            self.token_expiry = 0
