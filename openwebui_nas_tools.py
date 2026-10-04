"""
title: NAS tools
author: Nicolas THIBAUT
git_url: https://github.com/nicthbt/openwebui-nas-tools
description: Search on NAS for information and fetch specific file content.
license: AGPL-3.0-only
version: 1.5.0
required_open_webui_version: 0.10.2
requirements: requests, paramiko, smbprotocol
"""


import json
import logging
from hashlib import blake2b
import requests
import urllib3
import io
import mimetypes
import os
import re
import unicodedata
from contextvars import ContextVar
from difflib import SequenceMatcher
from fastapi import Request
from fastapi import UploadFile
from open_webui.internal.db import get_async_db_context
from open_webui.models.config import Config
from open_webui.models.files import Files
from open_webui.models.users import UserModel
from open_webui.retrieval.vector.async_client import ASYNC_VECTOR_DB_CLIENT
from open_webui.routers.files import upload_file_handler
from open_webui.routers.retrieval import ProcessFileForm
from open_webui.routers.retrieval import QueryCollectionsForm
from open_webui.routers.retrieval import process_file
from open_webui.routers.retrieval import query_collection_handler
from functools import wraps
import asyncio
import stat
import time
from datetime import datetime
import paramiko
import smbclient
from pydantic import BaseModel
from pydantic import Field


log = logging.getLogger(__name__)


class CustomToolException(Exception):
    def __init__(self, message, error=None):
        super().__init__(message)
        self.error = error


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


class OpenTerminalException(CustomToolException):
    pass


class OpenTerminalClient:
    def __init__(self, __request__, __metadata__):
        self.http = requests.Session()
        self.http.cookies.update(__request__.cookies)

        # Forward auth header
        authorization = __request__.headers.get("Authorization", None)
        if authorization is not None:
            self.http.headers.update({"Authorization": authorization})

        # Forward chat ID
        chat_id = __metadata__.get("chat_id", None)
        if chat_id is not None:
            self.http.headers.update({"X-Session-Id": chat_id})

        # Extract terminal ID
        terminal_id = __metadata__.get("terminal_id", None)
        if terminal_id is None:
            raise OpenTerminalException("No terminal set for this chat")

        # Extract internal server
        host, port = __request__.scope.get("server", None) or (None, None)
        if host is None or port is None:
            raise OpenTerminalException("Unable to detect internal server")

        # Build API routes
        self.server = f"http://{host}:{port}"
        self.api = {
            "CWD": __request__.app.url_path_for(
                "proxy_terminal",
                server_id=terminal_id,
                path="files/cwd",
            ).make_absolute_url(base_url=self.server),
            "UPLOAD": __request__.app.url_path_for(
                "proxy_terminal",
                server_id=terminal_id,
                path="files/upload",
            ).make_absolute_url(base_url=self.server),
            "VIEW": __request__.app.url_path_for(
                "proxy_terminal",
                server_id=terminal_id,
                path="files/view",
            ).make_absolute_url(base_url=self.server),
        }

    def __del__(self):
        self.http.close()

    def get_cwd(self, timeout: int = 10) -> str:
        response = self.http.get(
            self.api.get("CWD"),
            timeout=timeout,
        )
        response.raise_for_status()

        # Load response as JSON
        response_json = response.json()

        return response_json.get("cwd", None)

    def upload_file(
        self,
        filename: str,
        mimetype: str,
        content: bytes,
        directory: str = None,
        timeout: int = 60,
    ) -> dict:
        response = self.http.post(
            self.api.get("UPLOAD"),
            params={"directory": directory or self.get_cwd()},
            files={"file": (filename, content, mimetype or "application/octet-stream")},
            timeout=timeout,
        )
        response.raise_for_status()

        # Load response as JSON
        response_json = response.json()

        path = response_json.get("path", None)
        size = response_json.get("size", None)

        return {
            "path": path,
            "name": filename,
            "size": size,
            "content_type": mimetype,
        }

    def download_file(self, path: str, timeout: int = 60) -> bytes:
        response = self.http.get(
            self.api.get("VIEW"),
            params={"path": path},
            stream=True,
            timeout=timeout,
        )
        response.raise_for_status()

        content = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            content.extend(chunk)
        return bytes(content)


class CustomTool:
    def __init__(self, namespace):
        self.valves = self.Valves()
        self.context = ContextVar(namespace)
        self.namespace = namespace
        # Add missing mimetypes
        msoffice = {
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        }
        libreoffice = {
            ".odt": "application/vnd.oasis.opendocument.text",
            ".ods": "application/vnd.oasis.opendocument.spreadsheet",
            ".odp": "application/vnd.oasis.opendocument.presentation",
        }
        for extension, mimetype in msoffice.items():
            mimetypes.add_type(mimetype, extension)
        for extension, mimetype in libreoffice.items():
            mimetypes.add_type(mimetype, extension)

    def _is_media(
        self,
        mimetype: str,
        checklist: list = ["image/", "audio/", "video/"],
    ) -> bool:
        if mimetype is not None:
            return mimetype.startswith(tuple(checklist))
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

    def _sort_results(self, results: list, keys: list) -> list:
        # Sort by keys from lowest to highest priority
        for key, reverse in reversed(keys):
            results.sort(key=lambda result: result[key], reverse=reverse)
        return results[: self.valves.search_count]

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

    async def _query_collections(
        self,
        query: str,
        collections: list,
        __user__: dict,
        __request__: Request,
    ) -> list:
        # Query the collection using the retrieval engine
        collection_results = await query_collection_handler(
            __request__,
            QueryCollectionsForm(
                collection_names=collections,
                query=query,
            ),
            user=UserModel(**__user__),
        )

        results = {}

        # Generate query-focused results (instead of relying on raw results)
        for distances, metadatas, documents in zip(
            collection_results.get("distances", []),
            collection_results.get("metadatas", []),
            collection_results.get("documents", []),
        ):
            for distance, metadata, document in zip(distances, metadatas, documents):
                file_id = metadata.get("file_id")
                file_metadata = await Files.get_file_metadata_by_id(file_id)
                source = file_metadata.meta.get("source") or metadata.get("source")
                source_hash = blake2b(source.encode()).hexdigest()
                # Add new source to results or update existing source with new snippets
                snippets = results.get(source_hash, {}).get("snippets", [])
                snippets.append(document)
                # Add new source to results or update existing source with new snippets
                results.update(
                    {
                        source_hash: {
                            "id": file_id,
                            "source": source,
                            "snippets": snippets,
                        }
                    }
                )

        return list(results.values())

    async def _get_cache_file(
        self,
        file_hash: str,
        user: UserModel,
    ) -> tuple:
        cache_key = f"{self.namespace}.files.{user.id}.{file_hash}"
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
        cache_key = f"{self.namespace}.files.{user.id}.{file_hash}"
        cache_value = {
            "id": file_id,
            "collection": file_collection,
        }
        await Config.upsert({cache_key: cache_value})

    async def _upload_file(
        self,
        source: str,
        filename: str,
        mimetype: str,
        content: bytes,
        process: bool,
        __user__: dict,
        __request__: Request,
    ) -> tuple:
        async with get_async_db_context() as db:
            user = UserModel(**__user__)

            # Search for file in cache
            file_hash = blake2b(source.encode() + b"\0" + content).hexdigest()
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

            # Update source
            await Files.update_file_metadata_by_id(
                file_id,
                {"source": source},
                db=db,
            )

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

    async def _emit_sources(
        self,
        event_emitter,
        files: list,
    ) -> None:
        for file in files:
            file_id = file.get("id")
            source = file.get("source")
            filename = os.path.basename(source)
            snippets = file.get("snippets")
            if event_emitter:
                await event_emitter(
                    {
                        "type": "source",
                        "data": {
                            "source": {
                                "id": file_id,
                                "name": filename,
                                "type": "file",
                            },
                            "document": snippets,
                            "metadata": [
                                {
                                    "file_id": file_id,
                                    "name": filename,
                                    "source": source,
                                }
                                for snippet in snippets
                            ],
                        },
                    }
                )

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
                        "files": [
                            (
                                {**file, "type": "filesystem"}
                                if file.get("id", None) is None
                                else {**file, "type": "file"}
                            )
                            for file in files
                        ],
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

            connect_handler, *other_handlers = self._get_handlers()

            await self._emit_status(
                __event_emitter__,
                "Connecting to server...",
                done=False,
            )

            # Connect to server
            session = await connect_handler(__user__, __event_call__)

            # Set context for this call
            token = self.context.set((session, *other_handlers))

            return await func(self, *args, **kwargs)

        except CustomToolException as e:
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


class SambaCache(dict):
    def reset(self):
        smbclient.reset_connection_cache(
            fail_on_error=False,
            connection_cache=self,
        )


class Tools(CustomTool):
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
        super().__init__("tools.nas")

    def _get_credentials(self, config: dict) -> dict:
        if config.username is None:
            raise ValueError("Please configure NAS username")

        if config.password is None:
            raise ValueError("Please configure NAS password")

        return config.username.strip(), config.password.strip()

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

    async def _connect_api(
        self,
        __user__: dict,
        __event_call__: callable = None,
    ) -> SynologyClient:
        username, password = self._get_credentials(__user__.get("valves"))
        session = SynologyClient(
            host=self.valves.host,
            port=self.valves.port or 5001,
            verify=self.valves.verify_ssl,
        )

        try:
            session.api_auth_login(username, password)
        except SynologyOTPException:
            log.warning("Asking for OTP code to authenticate on API")
            otp_code = await self._ask_otp(__event_call__)
            session.api_auth_login(username, password, otp_code)

        return session

    async def _connect_sftp(
        self,
        __user__: dict,
        __event_call__: callable = None,
    ) -> paramiko.sftp_client.SFTPClient:
        username, password = self._get_credentials(__user__.get("valves"))
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
        __user__: dict,
        __event_call__: callable = None,
    ) -> SambaCache:
        username, password = self._get_credentials(__user__.get("valves"))
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

        count = 0
        total = 0
        end = False
        try:
            while not end:
                if int(time.monotonic()) >= timeout:
                    raise TimeoutError(
                        f"Timeout of search task after {self.valves.search_timeout} secs"
                    )

                time.sleep(1)

                data = session.api_fs_search_list(search_id, count)

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
                    count = count + 1

                # Verify task completion
                if count != total:
                    end = False

        except TimeoutError as e:
            log.warning(e)
        finally:
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
                        filetypes,
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
                        filetypes,
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

    def _filter_ext(self, filename: str, filetypes: list) -> bool:
        extension = os.path.splitext(filename)[-1]
        if filetypes:
            for filetype in filetypes:
                if extension == filetype or extension == f".{filetype}":
                    return True
        else:
            return True
        return False

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

    def _build_pattern(self, keywords: list) -> str:
        if len(keywords) == 0:
            return None
        # Replace non ascii characters by ?
        return " || ".join(keywords).encode("ascii", "replace").decode()

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
        Best for quickly identifying relevant files.

        :param query: The search keywords to look up without special operators or wildcards (optional)
        :param path: The root directory to recursively look into (optional, defaults to "/")
        :param filetypes: A list of file extensions to look for (optional, defaults to any)
        :return: JSON with results containing NAS path, filename, size in bytes, access time, modification time and search score of each file
        """
        session, browse_handler, download_handler = self.context.get()

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

        return json.dumps(results, ensure_ascii=False)

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
        :return: JSON with results containing file ID, source path and search snippets for each file
        """
        session, browse_handler, download_handler = self.context.get()

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
                path,
                filename,
                mimetype,
                content,
                process=True,
                __user__=__user__,
                __request__=__request__,
            )

            collections.append(file_collection)

        results = await self._query_collections(
            query,
            collections,
            __user__=__user__,
            __request__=__request__,
        )

        await self._emit_sources(
            __event_emitter__,
            results,
        )

        await self._emit_status(
            __event_emitter__,
            f"{len(results)} results found.",
            done=True,
        )

        return json.dumps(results, ensure_ascii=False)

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
        Fetch specific files from NAS and attach them to the conversation.
        Best for downloading raw files and processing them with other tools.

        :param files: A list of path for files to fetch
        :return: JSON with results containing file ID or filesystem path, filename, size in bytes and content type for each file
        """
        session, browse_handler, download_handler = self.context.get()

        await self._emit_status(
            __event_emitter__,
            f"Fetching {len(files)} files...",
            done=False,
        )

        # Init Open Terminal client
        terminal = None
        try:
            terminal = OpenTerminalClient(__request__, __metadata__)
        except OpenTerminalException as e:
            log.warning(e)

        results = []

        for path in files:
            filename = os.path.basename(path)
            mimetype, encoding = mimetypes.guess_type(filename)

            # Exclude video files
            if self._is_media(mimetype, checklist=["video/"]):
                raise TypeError(f"Invalid mimetype '{mimetype}' for '{path}'")

            log.info(f"Downloading '{path}'")
            content = await asyncio.to_thread(download_handler, session, path)

            if terminal is not None:
                # Upload file to Open Terminal
                result = await asyncio.to_thread(
                    terminal.upload_file,
                    filename,
                    mimetype,
                    content,
                )
                results.append(result)
            else:
                # Upload file but do not process content
                file_id, file_collection = await self._upload_file(
                    path,
                    filename,
                    mimetype,
                    content,
                    process=False,
                    __user__=__user__,
                    __request__=__request__,
                )
                result = {
                    "id": file_id,
                    "name": filename,
                    "size": len(content),
                    "content_type": mimetype,
                }
                results.append(result)

                # Add files to chat metadata for Pyodide
                __metadata__["files"].append(result)

        await self._emit_files(
            __event_emitter__,
            results,
        )

        await self._emit_status(
            __event_emitter__,
            f"{len(results)} results found.",
            done=True,
        )

        return json.dumps(results, ensure_ascii=False)
