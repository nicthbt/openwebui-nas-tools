"""
title: NAS tools
author: Nicolas THIBAUT
git_url: https://github.com/uppersafe/
description: Search on NAS for information and fetch specific file content.
license: AGPL-3.0-only
version: 1.2.6
required_open_webui_version: 0.10.2
requirements: requests, paramiko, smbprotocol
"""

import os
import io
import re
import time
import json
import stat
import unicodedata
import mimetypes
import asyncio
import logging
import urllib3
import requests
import paramiko
import smbclient
from hashlib import blake2b
from difflib import SequenceMatcher
from fastapi import Request, UploadFile
from pydantic import BaseModel, Field
from contextvars import ContextVar
from functools import wraps
from datetime import datetime

from open_webui.models.users import UserModel
from open_webui.models.config import Config
from open_webui.models.files import Files
from open_webui.internal.db import get_async_db_context
from open_webui.routers.files import upload_file_handler
from open_webui.retrieval.vector.async_client import ASYNC_VECTOR_DB_CLIENT
from open_webui.routers.retrieval import (
    ProcessFileForm,
    process_file,
    QueryCollectionsForm,
    query_collection_handler,
)

log = logging.getLogger(__name__)


class SambaCache(dict):
    def reset(self):
        smbclient.reset_connection_cache(
            fail_on_error=False,
            connection_cache=self,
        )


class SynologyAPIException(Exception):
    def __init__(self, message, error=None):
        super().__init__(message)
        self.error = error


class SynologyOTPException(SynologyAPIException):
    pass


class SynologySIDException(SynologyAPIException):
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
        data: dict = {},
        stream: bool = False,
        timeout: int = 10,
    ) -> dict | bytes:
        # Insert session ID to authenticate request
        if self.sid is not None:
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
            "query": str(",").join(api_names),
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


def with_context(func):
    @wraps(func)
    async def wrapper(self, *args, **kwargs):
        session = None
        token = None

        try:
            __request__ = kwargs.get("__request__", None)
            __user__ = kwargs.get("__user__", None)
            __metadata__ = kwargs.get("__metadata__", None)
            __event_emitter__ = kwargs.get("__event_emitter__", None)
            __event_call__ = kwargs.get("__event_call__", None)

            if __request__ is None:
                raise ValueError("Request context not available")
            if __user__ is None:
                raise ValueError("User context not available")
            if __metadata__ is None:
                raise ValueError("Metadata context not available")
            else:
                if __metadata__.get("files", None) is None:
                    __metadata__["files"] = []

            user = UserModel(**__user__)
            username, password = self._get_credentials(__user__.get("valves"))

            # Get handlers depending on protocol
            connect_handler, browse_handler, download_handler = self._get_handlers()

            await self._emit_status(
                __event_emitter__,
                "Connecting to NAS...",
                done=False,
            )

            # Connect to server
            session = await connect_handler(username, password, __event_call__)

            # Set context for this call
            token = self.context.set((user, session, browse_handler, download_handler))

            return await func(self, *args, **kwargs)

        except SynologyAPIException as e:
            log.error(f"{e} ({e.error})" if e.error else str(e))
            return json.dumps({"error": str(e)})

        except Exception as e:
            log.exception(e)
            return json.dumps({"error": str(e)})

        finally:
            # Reset context for this call
            if token is not None:
                self.context.reset(token)

            # Disconnect from server
            if session is not None:
                self._disconnect(session)

    return wrapper


class Tools:
    class UserValves(BaseModel):
        username: str = Field(
            title="NAS username",
            default=None,
        )
        password: str = Field(
            title="NAS password",
            default=None,
            json_schema_extra={"input": {"type": "password"}},
        )

    class Valves(BaseModel):
        protocol: str = Field(
            title="Protocol",
            default="api",
            json_schema_extra={
                "input": {
                    "type": "select",
                    "options": [
                        {"value": "api", "label": "API"},
                        {"value": "sftp", "label": "SFTP"},
                        {"value": "samba", "label": "Samba"},
                    ],
                }
            },
        )
        verify_ssl: bool = Field(
            title="SSL verification",
            default=True,
        )
        host: str = Field(
            title="Server hostname or IP address",
            default="host.docker.internal",
        )
        port: int | None = Field(
            title="Server port",
            default=None,
            ge=1,
            le=65535,
        )
        search_count: int = Field(
            title="Search result count",
            default=20,
        )
        search_timeout: int = Field(
            title="Search timeout",
            default=60,
        )

    def __init__(self):
        self.valves = self.Valves()
        self.context = ContextVar("tools.nas")
        self.namespace = "tools.nas.files"

    async def _connect_api(
        self,
        username: str,
        password: str,
        __event_call__=None,
    ) -> SynologyClient:
        session = SynologyClient(
            host=self.valves.host,
            port=self.valves.port or 5001,
            verify=self.valves.verify_ssl,
        )

        try:
            session.api_auth_login(username, password)
        except SynologyOTPException as e:
            log.warning("Asking for OTP code to authenticate on API")
            otp_code = await self._ask_otp(__event_call__)
            session.api_auth_login(username, password, otp_code)

        return session

    async def _connect_sftp(
        self,
        username: str,
        password: str,
        __event_call__=None,
    ) -> paramiko.sftp_client.SFTPClient:
        sshclient = paramiko.SSHClient()
        sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshclient.connect(
            hostname=self.valves.host,
            port=self.valves.port or 22,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        return sshclient.open_sftp()

    async def _connect_samba(
        self,
        username: str,
        password: str,
        __event_call__=None,
    ) -> SambaCache:
        cache = SambaCache()
        smbclient.register_session(
            server=self.valves.host,
            username=username,
            password=password,
            port=self.valves.port or 445,
            encrypt=True,
            connection_timeout=10,
            connection_cache=cache,
        )
        return cache

    def _disconnect(self, session) -> None:
        if hasattr(session, "api_auth_logout"):
            session.api_auth_logout()
        if hasattr(session, "close"):
            session.close()
        if hasattr(session, "reset"):
            session.reset()

    def _browse_api(
        self,
        session,
        query: str,
        path: str,
        filetypes: list,
        timeout: int = None,
    ) -> list:
        results = []
        timeout = timeout or int(time.monotonic() + self.valves.search_timeout)

        # Extract search keywords
        keywords = self._extract_keywords(query)

        # Build search pattern
        pattern = self._build_pattern(keywords)

        # Start search task
        search_id = session.api_fs_search_start(pattern, path)

        total = 0
        end = False
        try:
            while not end:
                if int(time.monotonic()) >= timeout:
                    raise TimeoutError(
                        f"Timeout of search task after {self.valves.search_timeout} secs"
                    )

                time.sleep(1)

                data = session.api_fs_search_list(search_id, len(results))

                entries = data.get("files", [])
                total = data.get("total", total)
                end = data.get("finished", False)

                log.info(f"Collecting {len(entries)} new search entries")

                for entry in entries:
                    entry_stat = entry.get("additional")
                    if self._filter_ext(entry.get("name"), filetypes):
                        results.append(
                            self._score_file(
                                entry.get("path"),
                                entry.get("name"),
                                entry_stat.get("size"),
                                entry_stat.get("time").get("atime"),
                                entry_stat.get("time").get("mtime"),
                                keywords,
                            )
                        )

                # Verify task completion
                if len(results) != total:
                    end = False

        except TimeoutError as e:
            log.warning(e)

        # Cleanup task
        session.api_fs_search_clean(search_id)

        # Sort results and return best matches
        return self._sort_results(results, [("score", True), ("mtime", True)])

    def _browse_sftp(
        self,
        session,
        query: str,
        path: str,
        filetypes: list,
        timeout: int = None,
    ) -> list:
        results = []
        timeout = timeout or int(time.monotonic() + self.valves.search_timeout)

        # Extract search keywords
        keywords = self._extract_keywords(query)

        try:
            if int(time.monotonic()) >= timeout:
                raise TimeoutError(
                    f"Timeout of search task after {self.valves.search_timeout} secs"
                )
            entries = session.listdir_attr(path)
            for entry in entries:
                entry_path = os.path.join(path, entry.filename)
                if stat.S_ISDIR(entry.st_mode):
                    for result in self._browse_sftp(
                        session,
                        query,
                        entry_path,
                        timeout,
                    ):
                        results.append(result)
                elif stat.S_ISREG(entry.st_mode):
                    if self._filter_ext(entry.filename, filetypes):
                        results.append(
                            self._score_file(
                                entry_path,
                                entry.filename,
                                entry.st_size,
                                entry.st_atime,
                                entry.st_mtime,
                                keywords,
                            )
                        )
                elif stat.S_ISLNK(entry.st_mode):
                    log.warning(f"Skipping link {entry_path}")

        except TimeoutError as e:
            log.warning(e)

        # Sort results and return best matches
        return self._sort_results(results, [("score", True), ("mtime", True)])

    def _browse_samba(
        self,
        session,
        query: str,
        path: str,
        filetypes: list,
        timeout: int = None,
    ) -> list:
        results = []
        timeout = timeout or int(time.monotonic() + self.valves.search_timeout)

        # Extract search keywords
        keywords = self._extract_keywords(query)

        try:
            if int(time.monotonic()) >= timeout:
                raise TimeoutError(
                    f"Timeout of search task after {self.valves.search_timeout} secs"
                )
            entries = smbclient.scandir(path, connection_cache=session)
            for entry in entries:
                entry_stat = entry.stat(follow_symlinks=False)
                if entry.is_dir():
                    for result in self._browse_samba(
                        session,
                        query,
                        entry.path,
                        timeout,
                    ):
                        results.append(result)
                elif entry.is_file():
                    if self._filter_ext(entry.name, filetypes):
                        results.append(
                            self._score_file(
                                entry.path,
                                entry.name,
                                entry_stat.st_size,
                                entry_stat.st_atime,
                                entry_stat.st_mtime,
                                keywords,
                            )
                        )
                elif entry.is_symlink():
                    log.warning(f"Skipping link {entry.path}")

        except TimeoutError as e:
            log.warning(e)

        # Sort results and return best matches
        return self._sort_results(results, [("score", True), ("mtime", True)])

    def _download_api(self, session, path: str) -> bytes:
        return session.api_fs_download(path)

    def _download_sftp(self, session, path: str) -> bytes:
        content = bytearray()
        with session.open(path, mode="rb") as file:
            while chunk := file.read(65536):
                content.extend(chunk)
        return bytes(content)

    def _download_samba(self, session, path: str) -> bytes:
        content = bytearray()
        with smbclient.open_file(path, mode="rb", connection_cache=session) as file:
            while chunk := file.read(65536):
                content.extend(chunk)
        return bytes(content)

    def _get_handlers(self) -> tuple:
        # Return handlers
        match self.valves.protocol:
            case "api":
                connect_handler = self._connect_api
                browse_handler = self._browse_api
                download_handler = self._download_api

            case "sftp":
                connect_handler = self._connect_sftp
                browse_handler = self._browse_sftp
                download_handler = self._download_sftp

            case "samba":
                connect_handler = self._connect_samba
                browse_handler = self._browse_samba
                download_handler = self._download_samba

            case _:
                raise ValueError("Unknown protocol")

        return connect_handler, browse_handler, download_handler

    def _get_credentials(self, config: dict) -> dict:
        if config.username is None:
            raise ValueError("Please configure NAS username")

        if config.password is None:
            raise ValueError("Please configure NAS password")

        return config.username.strip(), config.password.strip()

    def _filter_ext(self, filename: str, filetypes: list) -> bool:
        extension = os.path.splitext(filename)[-1]
        if filetypes:
            for filetype in filetypes:
                if extension == filetype or extension == f".{filetype}":
                    return True
        else:
            return True
        return False

    def _seq_match(self, text: str, keywords: list) -> list:
        # Normalize text in ascii characters
        nfkd_text = (
            unicodedata.normalize("NFKD", text.lower())
            .encode("ascii", "ignore")
            .decode()
        )
        # Normalize keywords in ascii characters
        nfkd_keywords = [
            unicodedata.normalize("NFKD", keyword.lower())
            .encode("ascii", "ignore")
            .decode()
            for keyword in keywords
        ]

        # Get the match length for each keyword
        return [
            SequenceMatcher(None, nfkd_keyword, nfkd_text).find_longest_match().size
            for nfkd_keyword in nfkd_keywords
        ]

    def _score_file(
        self,
        path: str,
        name: str,
        size: int,
        atime: int,
        mtime: int,
        keywords: list,
    ) -> dict:
        # Initialize score to zero
        score = 0

        # Calculate the keywords total length
        total_length = sum(len(keyword) for keyword in keywords)

        # Guess mimetype from filename
        mimetype, encoding = mimetypes.guess_type(name)

        # Lower weight for image, audio and video files
        match_weight = 0.5 if self._is_media(mimetype) else 1.0

        # Calculate the weight of one character
        match_weight = match_weight / max(1.0, total_length)

        if path is not None:
            # Calculate match with absolute path
            score = score + sum(
                match_size * match_weight
                for match_size in self._seq_match(path, keywords)
            )

        return self._format_result(path, name, size, atime, mtime, score)

    def _format_result(
        self,
        path: str,
        name: str,
        size: int,
        atime: int,
        mtime: int,
        score: float = None,
    ) -> dict:
        result = {
            "path": path,
            "name": name,
            "size": size,
            "atime": datetime.fromtimestamp(atime).astimezone().isoformat(),
            "mtime": datetime.fromtimestamp(mtime).astimezone().isoformat(),
        }
        if score is not None:
            result.update({"score": score})
        return result

    def _sort_results(self, results: list, keys: list) -> list:
        # Sort by keys from lowest to highest priority
        for key, reverse in reversed(keys):
            results.sort(key=lambda result: result[key], reverse=reverse)
        return results[: self.valves.search_count]

    def _is_media(
        self,
        mimetype: str,
        checklist: list = ["image/", "audio/", "video/"],
    ) -> bool:
        if mimetype is not None:
            return mimetype.startswith(tuple(checklist))
        return False

    def _build_pattern(self, keywords: list) -> str:
        if len(keywords) == 0:
            return None
        # Replace non ascii characters by ?
        return str(" || ").join(keywords).encode("ascii", "replace").decode()

    def _extract_keywords(self, query: str) -> list:
        if query is None or len(query.strip()) == 0:
            return []

        # Split query on special characters (space, tab, comma, etc) and remove linking words
        keywords = set(
            keyword.strip()
            for keyword in re.split(r"[';,\s\t\r\n]+", query)
            if len(keyword.strip()) > 1
        )

        # Check that keywords are not empty
        if len(keywords) == 0:
            raise ValueError(f"Cannot build keywords from query string '{query}'")

        return list(keywords)

    async def _get_cache_file(
        self,
        file_hash: str,
        user: UserModel,
    ) -> tuple:
        cache_key = f"{self.namespace}.{user.id}.{file_hash}"
        cache_value = await Config.get(cache_key, {})

        file_id = cache_value.get("id", None)
        file_collection = cache_value.get("collection", None)

        cleanup = False

        if file_id is not None:
            file = await Files.get_file_by_id(file_id)
            if not file:
                cleanup = True

        if file_collection is not None:
            collection = await ASYNC_VECTOR_DB_CLIENT.has_collection(file_collection)
            if not collection:
                cleanup = True

        # Delete cache if file or collection no longer exist
        if cleanup:
            log.warning(f"Deleting cache for {cache_key}")
            await Config.delete(cache_key)
            return None, None

        return file_id, file_collection

    async def _set_cache_file(
        self,
        file_hash: str,
        file_id: str,
        file_collection: str,
        user: UserModel,
    ) -> None:
        cache_key = f"{self.namespace}.{user.id}.{file_hash}"
        cache_value = {
            "id": file_id,
            "collection": file_collection,
        }
        await Config.upsert({cache_key: cache_value})

    async def _upload_file(
        self,
        filename: str,
        mimetype: str,
        content: bytes,
        process: bool,
        user: UserModel,
        __request__: Request,
    ) -> tuple:
        async with get_async_db_context() as db:
            # Search for file in cache
            file_hash = blake2b(content).hexdigest()
            file_id, file_collection = await self._get_cache_file(
                file_hash,
                user=user,
            )

            # Upload file if not in cache
            if file_id is None:
                log.info(f"Uploading '{filename}'")
                file = await upload_file_handler(
                    __request__,
                    UploadFile(
                        file=io.BytesIO(content),
                        filename=filename,
                        headers={"content-type": mimetype},
                    ),
                    metadata={},
                    process=False,
                    user=user,
                    db=db,
                )
                file_id = file.id

            # Process file if not in cache
            if file_collection is None and process is True:
                log.info(f"Processing '{filename}'")
                result = await process_file(
                    __request__,
                    ProcessFileForm(file_id=file_id),
                    user=user,
                    db=db,
                )
                file_collection = result.get("collection_name")

            await self._set_cache_file(
                file_hash,
                file_id,
                file_collection,
                user=user,
            )

            return file_id, file_collection

    async def _emit_files(
        self,
        event_emitter,
        files: list,
    ) -> None:
        if event_emitter:
            await event_emitter(
                {
                    "type": "files",
                    "data": {
                        "files": [{**file, "type": "file"} for file in files],
                    },
                }
            )

    async def _emit_status(
        self,
        event_emitter,
        desc: str,
        done: bool = False,
        hidden: bool = False,
    ) -> None:
        if event_emitter:
            await event_emitter(
                {
                    "type": "status",
                    "data": {
                        "description": desc,
                        "done": done,
                        "hidden": hidden,
                    },
                }
            )

    async def _ask_otp(
        self,
        __event_call__,
    ) -> str | None:
        if __event_call__:
            return await __event_call__(
                {
                    "type": "input",
                    "data": {
                        "title": "Synology OTP",
                        "message": "Please enter your code",
                        "placeholder": "123456",
                    },
                }
            )
        return None

    @with_context
    async def search_nas_files(
        self,
        query: str = None,
        path: str = "/",
        filetypes: list = [],
        __request__: Request = None,
        __user__: dict = None,
        __metadata__: dict = None,
        __event_emitter__: callable = None,
        __event_call__: callable = None,
    ) -> str:
        """
        Search for files on NAS.
        Best to quickly identify relevant files.

        :param query: The search keywords to look up without special operators or wildcards (optional)
        :param path: The root directory to recursively look into (optional, defaults to "/")
        :param filetypes: A list of file extensions to look for (optional, defaults to any)
        :return: JSON with results containing absolute path, filename, size in bytes, access time, modification time and search score of each file
        """
        user, session, browse_handler, download_handler = self.context.get()

        await self._emit_status(
            __event_emitter__,
            "Searching for files...",
            done=False,
        )

        # Browse files
        results = await asyncio.to_thread(
            browse_handler,
            session,
            query,
            path,
            filetypes,
        )

        await self._emit_status(
            __event_emitter__,
            f"{len(results)} files found.",
            done=True,
        )

        return json.dumps(list(results), ensure_ascii=False)

    @with_context
    async def inspect_nas_files(
        self,
        query: str,
        files: list,
        __request__: Request = None,
        __user__: dict = None,
        __metadata__: dict = None,
        __event_emitter__: callable = None,
        __event_call__: callable = None,
    ) -> str:
        """
        Search for information in specific files on NAS.
        Best for semantic content retrieval.

        :param query: The search query to look up with the RAG engine
        :param files: A list of path for files to look into
        :return: JSON with results containing file ID, filename and search snippets for each file
        """
        user, session, browse_handler, download_handler = self.context.get()

        await self._emit_status(
            __event_emitter__,
            f"Inspecting {len(files)} files...",
            done=False,
        )

        collections = []

        for path in files:
            filename = os.path.basename(path)
            mimetype, encoding = mimetypes.guess_type(filename)

            # Exclude audio and video files
            if self._is_media(mimetype, checklist=["audio/", "video/"]):
                raise TypeError(f"Invalid mimetype '{mimetype}' for '{path}'")

            log.info(f"Downloading '{path}'")
            content = await asyncio.to_thread(download_handler, session, path)

            # Upload file and process content
            file_id, file_collection = await self._upload_file(
                filename,
                mimetype,
                content,
                process=True,
                user=user,
                __request__=__request__,
            )

            collections.append(file_collection)

        # Query the collection using the retrieval engine
        collection_results = await query_collection_handler(
            __request__,
            QueryCollectionsForm(
                collection_names=collections,
                query=query,
            ),
            user=user,
        )

        results = {}

        # Generate query-focused results (instead of relying on raw results)
        for distances, metadatas, documents in zip(
            collection_results.get("distances", []),
            collection_results.get("metadatas", []),
            collection_results.get("documents", []),
        ):
            for distance, metadata, document in zip(distances, metadatas, documents):
                name = metadata.get("name")
                source = metadata.get("file_id")
                source_hash = blake2b(source.encode()).hexdigest()
                # Get existing snippets if source already in results
                snippets = results.get(source_hash, {}).get("snippets", [])
                # Add new source to results or update existing source with new snippets
                results.update(
                    {
                        source_hash: {
                            "id": source,
                            "name": name,
                            "snippets": snippets + [document],
                        }
                    }
                )

        await self._emit_status(
            __event_emitter__,
            f"{len(results)} results found.",
            done=True,
        )

        return json.dumps(list(results.values()), ensure_ascii=False)

    @with_context
    async def fetch_nas_files(
        self,
        files: list,
        __request__: Request = None,
        __user__: dict = None,
        __metadata__: dict = None,
        __event_emitter__: callable = None,
        __event_call__: callable = None,
    ) -> str:
        """
        Fetch specific files on NAS and generate download URL.
        Best for raw content retrieval.

        :param files: A list of path for files to fetch
        :return: JSON with results containing file ID, filename, size in bytes, content type and download URL for each file
        """
        user, session, browse_handler, download_handler = self.context.get()

        await self._emit_status(
            __event_emitter__,
            f"Fetching {len(files)} files...",
            done=False,
        )

        results = {}

        for path in files:
            filename = os.path.basename(path)
            mimetype, encoding = mimetypes.guess_type(filename)

            # Exclude video files
            if self._is_media(mimetype, checklist=["video/"]):
                raise TypeError(f"Invalid mimetype '{mimetype}' for '{path}'")

            log.info(f"Downloading '{path}'")
            content = await asyncio.to_thread(download_handler, session, path)

            # Upload file but do not process content
            file_id, file_collection = await self._upload_file(
                filename,
                mimetype,
                content,
                process=False,
                user=user,
                __request__=__request__,
            )

            # Build download link
            results.update(
                {
                    file_id: {
                        "id": file_id,
                        "name": filename,
                        "size": len(content),
                        "content_type": mimetype,
                        "url": __request__.app.url_path_for(
                            "get_file_content_by_id",
                            id=file_id,
                            file_name=filename,
                        ),
                    }
                }
            )

        # Add files to chat metadata
        __metadata__["files"].extend(list(results.values()))

        await self._emit_files(
            __event_emitter__,
            list(results.values()),
        )

        await self._emit_status(
            __event_emitter__,
            f"{len(results)} results found.",
            done=True,
        )

        return json.dumps(list(results.values()), ensure_ascii=False)
