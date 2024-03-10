import socket

import ssl

from aiohttp import web
import aiofiles
import json
import os.path
import configparser

from logs.logger import logger
from ssl_certificate_generator import generate_self_signed_certificate, save_certificate, save_key

config = configparser.ConfigParser()
config.read('settings.ini')

port = config.getint('Server', 'port')
request_max_size = config.getint('Server', 'request_max_size') ** 5
hash_table_path = config.get('Paths', 'hash_table_path')
upload_directory = config.get('Paths', 'upload_directory')
last_ip_path = config.get('Paths', 'last_ip_path')
key_path = config.get('Paths', 'key_path')
cert_path = config.get('Paths', 'cert_path')


routes = web.RouteTableDef()
hash_table = {}


def load_data() -> None:
    global hash_table
    if not os.path.exists(hash_table_path):
        with open(hash_table_path, 'x'):
            hash_table = {}
            return

    with open(hash_table_path, 'r', encoding='utf-8') as file:
        try:
            hash_table = json.load(file)
        except json.decoder.JSONDecodeError as e:
            logger.error(f"Error parsing file {e.doc} at {e.pos} position: {e.msg}")
            hash_table = {}


def save_data() -> None:
    with open(hash_table_path, 'w+', encoding='utf-8') as file:
        json.dump(hash_table, file, ensure_ascii=False)


def is_new_ip(current_ip: str) -> bool:
    """
    Checks if the current IP is different from the last recorder one

    Returns:
        bool: True if the IP is the current IP is different or if there was an error parsing the last IP address;
            False otherwise
    """
    if not os.path.exists(last_ip_path):
        return True

    with open(last_ip_path, 'r') as file:
        try:
            last_ip = json.load(file)
            if last_ip == current_ip:
                return False
            else:
                return True
        except json.decoder.JSONDecodeError as e:
            logger.error(f"Error parsing last ip address")
            return True


def update_ip(current_ip: str) -> None:
    with open(last_ip_path, 'w+', encoding='utf-8') as file:
        json.dump(current_ip, file, ensure_ascii=False)


def get_ip() -> str:
    """
    Retrieve the local IP address of the current machine.

    This function tries to determine the local IP address of the machine by creating a
    temporary socket connection. If successful, it retrieves the IP address using the
    `getsockname()` method. If an exception occurs during the process, it defaults to
    returning the loopback address '127.0.0.1'.

    Returns:
        str: The local IP address of the current machine.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip


@routes.get('/get_data')
async def get_data(request) -> web.Response:
    logger.debug(f"Request received: {request}")
    return web.json_response(hash_table)


@routes.post('/file_hash_update')
async def file_hash_update(request) -> web.Response:
    data = await request.post()
    file_field = data['file']
    file_content = file_field.file.read()

    payload = json.loads(data['payload'])
    file_path = payload.get('file_path')
    relative_path = payload.get('relative_path')
    file_hash = payload.get('file_hash')

    upload_path = get_upload_path(relative_path)

    async with aiofiles.open(upload_path, 'wb') as f:
        await f.write(file_content)

    hash_table[file_path] = file_hash

    return web.Response(text="File update successfully")


@routes.post('/file_name_update')
async def file_name_update(request) -> web.Response:
    data = await request.json()
    new_path = data.get("file_path")
    new_rel_path = data.get('relative_path')
    old_path = data.get("old_path")
    old_rel_path = data.get('old_relative_path')

    if os.path.isfile(old_path):
        # removing from the list of files on server
        file_hash = hash_table[old_path]
        hash_table[new_path] = file_hash
        del hash_table[old_path]

    old_rel_path = get_upload_path(old_rel_path)
    new_rel_path = get_upload_path(new_rel_path)

    os.rename(old_rel_path, new_rel_path)
    return web.json_response("Name updated!")


@routes.delete('/delete_file')
async def delete_file(request) -> web.Response:
    data = await request.json()
    client_path = data.get("file_path")
    relative_path = data.get("relative_path")

    server_path = get_upload_path(relative_path)
    os.remove(server_path)
    del hash_table[client_path]

    return web.json_response("Deleted!")


def get_upload_path(relative_path: str) -> str:
    """
    Returns:
         str: The absolute path for a given relative path
    """
    upload_path = os.path.join(upload_directory, relative_path)

    # creating directories to create the file
    path_with_dirs = os.path.dirname(upload_path)
    os.makedirs(path_with_dirs, exist_ok=True)

    return upload_path


def main():
    current_ip = get_ip()

    if is_new_ip(current_ip):
        logger.debug(f"Server running on new ip: '{current_ip}'")
        private_key, certificate = generate_self_signed_certificate(current_ip)
        save_key(private_key)
        save_certificate(certificate)

        # save new ip as the last used
        update_ip(current_ip)

    # load saved data
    load_data()

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(cert_path, key_path)

    try:
        app = web.Application(client_max_size=request_max_size)
        app.add_routes(routes)
        web.run_app(app, host=current_ip, port=port, ssl_context=ssl_context)
    finally:
        save_data()


if __name__ == '__main__':
    main()
