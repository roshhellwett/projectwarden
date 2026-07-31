from ..core.paths import get_vault_dir

CLIENT_CONFIG = {
    "installed": {
        "client_id": "404572380586-mmt4kcaqs7svqn1dqq237o47jr6ikimb.apps.googleusercontent.com",
        "client_secret": "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",
        "project_id": "zenith-passkeys",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "redirect_uris": ["http://localhost"],
    }
}

SCOPES = ["https://www.googleapis.com/auth/drive.appdata"]

class GDriveProvider:
    def __init__(self):
        self.token_path = get_vault_dir() / "gdrive_token.json"
        self.service = None

    def is_authenticated(self) -> bool:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        if not self.token_path.exists():
            return False
        creds = Credentials.from_authorized_user_file(str(self.token_path), SCOPES)
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            with open(self.token_path, "w") as f:
                f.write(creds.to_json())
        self.service = self._build_service(creds)
        return creds.valid

    def authenticate(self) -> None:
        from google_auth_oauthlib.flow import InstalledAppFlow
        flow = InstalledAppFlow.from_client_config(CLIENT_CONFIG, SCOPES)
        creds = flow.run_local_server(open_browser=True)
        with open(self.token_path, "w") as f:
            f.write(creds.to_json())
        self.token_path.chmod(0o600)
        self.service = self._build_service(creds)

    def _build_service(self, creds):
        from googleapiclient.discovery import build
        return build("drive", "v3", credentials=creds)

    def upload(self, encrypted_blob: bytes, metadata: dict) -> None:
        from googleapiclient.http import MediaIoBaseUpload
        import io
        if not self.service:
            raise RuntimeError("Not authenticated")
        media = MediaIoBaseUpload(io.BytesIO(encrypted_blob), mimetype="application/octet-stream", resumable=True)
        self.service.files().create(
            body={"name": metadata.get("name", "zenith-vault-backup.enc"), "parents": ["appDataFolder"]},
            media_body=media,
        ).execute()

    def download(self) -> tuple[bytes, dict]:
        if not self.service:
            raise RuntimeError("Not authenticated")
        results = self.service.files().list(spaces="appDataFolder", pageSize=1).execute()
        files = results.get("files", [])
        if not files:
            return (b"", {})
        file_id = files[0]["id"]
        data = self.service.files().get_media(fileId=file_id).execute()
        return (data, files[0])

    def revoke(self) -> None:
        if self.token_path.exists():
            self.token_path.unlink()
