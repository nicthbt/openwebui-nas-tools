import json
import logging
from hashlib import blake2b

import requests
import urllib3

from src.common.exceptions import CustomToolException

log = logging.getLogger(__name__)


class SynologyAPIException(CustomToolException):
    pass


class SynologyOTPException(CustomToolException):
    pass


class SynologySIDException(CustomToolException):
    pass


class SynologyClient:
    def __init__(
        self,
        host: str,
        port: int,
        verify: bool = True,
    ):
        self.http = requests.Session()
        if not verify:
            self.http.verify = verify
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.device_name = "open-webui"
        self.device_id = blake2b(self.device_name.encode()).hexdigest()
        self.sid = None
        self.api = self._api_info(host=host, port=port)

    def __del__(self):
        self.http.close()

    def _api_call(
        self,
        url: str,
        data: dict = None,
        stream: bool = False,
        timeout: int = 10,
    ) -> dict | bytes:
        # Insert session ID to authenticate request
        if self.sid is not None:
            data = data or {}
            data.update({"_sid": self.sid})

        response = self.http.get(
            url,
            params=data,
            stream=stream,
            timeout=timeout,
        )
        response.raise_for_status()

        # Load response as bytes to retrieve files
        if stream:
            content = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                content.extend(chunk)
            return bytes(content)

        # Load response as JSON
        response_json = response.json()

        if "error" in response_json:
            raise SynologyAPIException("API error", response_json.get("error"))

        return response_json.get("data")

    def _api_info(self, host: str, port: int) -> dict:
        api_names = [
            "SYNO.API.Auth",
            "SYNO.FileStation.List",
            "SYNO.FileStation.Search",
            "SYNO.FileStation.Download",
        ]

        data = {
            "api": "SYNO.API.Info",
            "version": 1,
            "method": "query",
            "query": ",".join(api_names),
        }

        response = self._api_call(f"https://{host}:{port}/webapi/query.cgi", data)

        api = {}

        for api_name in api_names:
            if response.get(api_name, None) is not None:
                api_path = response.get(api_name).get("path")
                api_version = response.get(api_name).get("maxVersion")
                api_url = f"https://{host}:{port}/webapi/{api_path}"
                api.update({api_name: (api_url, api_version)})
            else:
                raise SynologyAPIException("Incomplete API info")

        return api

    def api_auth_login(
        self,
        username: str,
        password: str,
        otp_code: str | None = None,
    ) -> str:
        api_url, api_version = self.api.get("SYNO.API.Auth")

        data = {
            "api": "SYNO.API.Auth",
            "version": api_version,
            "method": "login",
            "account": username,
            "passwd": password,
            "device_name": self.device_name,
            "device_id": self.device_id,
            "enable_device_token": "yes",
            "session": "FileStation",
            "format": "sid",
        }

        if otp_code is not None:
            data.update({"otp_code": otp_code})

        try:
            response = self._api_call(api_url, data)
            self.sid = response.get("sid")

        except SynologyAPIException as e:
            otp_error = any(
                [
                    error_type.get("type") == "otp"
                    for error_type in e.error.get("errors", {}).get("types", [])
                ]
            )
            if otp_error:
                raise SynologyOTPException("Invalid OTP", e.error)
            else:
                raise SynologySIDException("Invalid username or password", e.error)

        return self.sid

    def api_auth_logout(self) -> dict:
        api_url, api_version = self.api.get("SYNO.API.Auth")

        data = {
            "api": "SYNO.API.Auth",
            "version": api_version,
            "method": "logout",
        }

        response = self._api_call(api_url, data)

        return response

    def api_fs_list(self) -> list:
        api_url, api_version = self.api.get("SYNO.FileStation.List")

        data = {
            "api": "SYNO.FileStation.List",
            "version": api_version,
            "method": "list_share",
            "offset": 0,
            "limit": 0,
        }

        response = self._api_call(api_url, data)

        shares = [
            share.get("path")
            for share in response.get("shares")
            if share.get("isdir") and share.get("path")
        ]

        if len(shares) == 0:
            raise SynologyAPIException("Error while looking for shares (no one found)")

        return shares

    def api_fs_search_start(self, pattern: str, path: str) -> str:
        api_url, api_version = self.api.get("SYNO.FileStation.Search")

        path = path.rstrip("/") if path != "/" else self.api_fs_list()

        data = {
            "api": "SYNO.FileStation.Search",
            "version": api_version,
            "method": "start",
            "recursive": True,
            "folder_path": json.dumps(path, separators=(",", ":")),
            "filetype": json.dumps("file", separators=(",", ":")),
        }

        if pattern is not None:
            data.update({"pattern": json.dumps(pattern, separators=(",", ":"))})

        response = self._api_call(api_url, data)

        if "taskid" not in response:
            raise SynologyAPIException(
                "Error while starting search (task ID not found)"
            )

        return response.get("taskid")

    def api_fs_search_list(self, taskid: str, offset: int = 0) -> dict:
        api_url, api_version = self.api.get("SYNO.FileStation.Search")

        data = {
            "api": "SYNO.FileStation.Search",
            "version": api_version,
            "method": "list",
            "taskid": json.dumps(taskid, separators=(",", ":")),
            "offset": offset,
            "limit": 100,
            "additional": json.dumps(["size", "time"], separators=(",", ":")),
        }

        response = self._api_call(api_url, data)

        return response

    def api_fs_search_clean(self, taskid: str) -> dict:
        api_url, api_version = self.api.get("SYNO.FileStation.Search")

        data = {
            "api": "SYNO.FileStation.Search",
            "version": api_version,
            "method": "clean",
            "taskid": json.dumps(taskid, separators=(",", ":")),
        }

        response = self._api_call(api_url, data)

        return response

    def api_fs_download(self, path: str) -> bytes:
        api_url, api_version = self.api.get("SYNO.FileStation.Download")

        data = {
            "api": "SYNO.FileStation.Download",
            "version": api_version,
            "method": "download",
            "path": json.dumps([path], separators=(",", ":")),
            "mode": json.dumps("open", separators=(",", ":")),
        }

        response = self._api_call(
            api_url,
            data,
            stream=True,
            timeout=60,
        )

        return response
