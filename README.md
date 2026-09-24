# Open WebUI NAS tools

Search on NAS for information and fetch specific file content using Open WebUI's RAG engine.

## Features

- Searches for files recursively.
- Ranks search results using keywords scoring and modification time.
- Downloads files and processes content in vector database (except image, audio, and video files).
- Caches files by content hash.
- Inspects files and retrieves relevant parts.
- Secures identity and access management with isolated/user-based authentication.
- Supports multiple protocols:
  - Synology DSM/FileStation API (including OTP prompt for authentication)
  - SFTP
  - Samba/SMB

## Available tools

### `search_nas_files`

Searches for files on the NAS and returns metadata.

Input parameters:

| Parameter | Description |
|---|---|
| `query` | Search query (optional). |
| `path` | Root directory for recursive search (optional, defaults to `/`). |
| `filetypes` | List of file extensions (optional, defaults to any). |

The output contains for each result:

- Absolute path
- Filename
- Size in bytes
- Access time
- Modification time
- Search score

### `inspect_nas_files`

Retrieves specific files from NAS and uses Open WebUI's retrieval engine to find relevant parts.

Input parameters:

| Parameter | Description |
|---|---|
| `query` | Search query. |
| `files` | List of NAS files. |

The output contains for each result:

- Open WebUI file ID
- Filename
- Text snippets

### `fetch_nas_files`

Retrieves specific files from NAS and uses Open WebUI's file upload system to generate download links.

Input parameters:

| Parameter | Description |
|---|---|
| `files` | List of NAS files. |

The output contains for each result:

- Open WebUI file ID
- Filename
- Size in bytes
- Content type
- Download URL

## Installation

1. Go to `Workspace` in Open WebUI.
2. Create a new tool from the `Tools` tab.
3. Paste the content of `openwebui_nas_tools.py` and save the tool.
4. Enable the tool in your custom model in `Models`.
5. Configure the tool valves to change default settings.
6. Configure the NAS username and password for each user.

## Configuration

### User Valves

| Setting | Description |
|---|---|
| `username` | NAS account username. |
| `password` | NAS account password. |

### Tool Valves

| Setting | Default | Description |
|---|---:|---|
| `protocol` | `api` | Connection method: `api`, `sftp`, or `samba`. |
| `verify_ssl` | `true` | SSL certificates verification. |
| `host` | `host.docker.internal` | NAS hostname or IP address reachable from the Open WebUI container. |
| `port` | Protocol default | Optional custom server port. |
| `search_count` | `20` | Maximum number of search results to return. |
| `search_timeout` | `60` | Maximum search task duration in seconds. |

When `port` is not set, the protocol default port is used:

| Protocol | Default port |
|---|---:|
| DSM/FileStation API | `5001` |
| SFTP | `22` |
| Samba/SMB | `445` |

## Security

**Enable encryption** to securely store credentials:
- Set `WEBUI_SECRET_KEY` (generate a secure key with `openssl rand -hex 32`).
- Set `ENABLE_VALVE_ENCRYPTION` to `true`.

Restrict network access between Open WebUI and the calendar server.

## Compatibility

Tested with **Open WebUI 0.10.2**.

The tool imports internal Open WebUI modules, so compatibility with earlier or later releases is not guaranteed.

## Requirements

Allow Open WebUI to install listed requirements:
- Set `ENABLE_PIP_INSTALL_FRONTMATTER_REQUIREMENTS` to `true`.
- Set `OFFLINE_MODE` to `false`.

The tool relies on 3rd party Python packages:
- [requests](https://github.com/psf/requests) (for Synology API)
- [paramiko](https://github.com/paramiko/paramiko) (for SFTP)
- [smbprotocol](https://github.com/jborean93/smbprotocol) (for Samba/SMB)

## License

[GNU AGPLv3](LICENSE)
