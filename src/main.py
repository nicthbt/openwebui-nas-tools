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

import asyncio
import json
import logging
import mimetypes
import os
import stat
import time
from datetime import datetime

import paramiko
import smbclient
from fastapi import Request
from pydantic import BaseModel, Field

from src.clients.synology_client import SynologyClient, SynologyOTPException
from src.clients.terminal_client import OpenTerminalClient, OpenTerminalException
from src.common.base import CustomTool
from src.common.decorators import with_context

log = logging.getLogger(__name__)


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
