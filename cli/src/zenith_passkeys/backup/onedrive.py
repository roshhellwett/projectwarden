from ..core.paths import get_vault_dir

CLIENT_ID = "ab9a8b3c-7d4e-5f6g-7h8i-9j0k1l2m3n4o"
AUTHORITY = "https://login.microsoftonline.com/consumers"
SCOPES = ["Files.ReadWrite.AppFolder"]

class OneDriveProvider:
    def __init__(self):
        self.token_path = get_vault_dir() / "onedrive_token.json"
        self.access_token = None

    def is_authenticated(self) -> bool:
        if not self.token_path.exists():
            return False
        import json
        with open(self.token_path) as f:
            token_data = json.load(f)
        from msal import PublicClientApplication
        app = PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
        result = app.acquire_token_silent(SCOPES, account=None)
        if result:
            self.access_token = result["access_token"]
            return True
        return False

    def authenticate(self) -> None:
        from msal import PublicClientApplication
        app = PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            raise RuntimeError(f"Device flow failed: {flow}")
        print(f"Open {flow['verification_uri']} and enter code: {flow['user_code']}")
        result = app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise RuntimeError(f"Auth failed: {result.get('error_description')}")
        self.access_token = result["access_token"]
        import json
        with open(self.token_path, "w") as f:
            json.dump(result, f)
        self.token_path.chmod(0o600)

    def upload(self, encrypted_blob: bytes, metadata: dict) -> None:
        import requests
        url = "https://graph.microsoft.com/v1.0/me/drive/special/approot:/zenith-vault-backup.enc:/content"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        resp = requests.put(url, headers=headers, data=encrypted_blob)
        resp.raise_for_status()

    def download(self) -> tuple[bytes, dict]:
        import requests
        url = "https://graph.microsoft.com/v1.0/me/drive/special/approot:/zenith-vault-backup.enc:/content"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        resp = requests.get(url, headers=headers)
        if resp.status_code == 404:
            return (b"", {})
        resp.raise_for_status()
        return (resp.content, {})

    def revoke(self) -> None:
        if self.token_path.exists():
            self.token_path.unlink()
