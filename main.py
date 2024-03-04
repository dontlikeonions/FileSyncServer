import ssl

from aiohttp import web
import aiofiles
import json
import os.path
import configparser

from logs.logger import logger

config = configparser.ConfigParser()
config.read('settings.ini')

ip = config.get('Server', 'ip')
port = config.getint('Server', 'port')
request_max_size = config.getint('Server', 'request_max_size') ** 5
hash_table_path = config.get('Paths', 'hash_table_path')
upload_directory = config.get('Paths', 'upload_directory')


routes = web.RouteTableDef()
hash_table = {}


def load_data() -> None:
    global hash_table
    if not os.path.exists(hash_table_path):
        with open(hash_table_path, 'x'):
            pass

    with open(hash_table_path, 'r+') as file:
        try:
            hash_table = json.load(file)
        except json.decoder.JSONDecodeError as e:
            logger.error(f"Error parsing file {e.doc} at {e.pos} position: {e.msg}")
            hash_table = {}


def save_data() -> None:
    with open(hash_table_path, 'w+') as file:
        json.dump(hash_table, file)


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
        # while chunk := await file.read(1024**2):
        #     await f.write(chunk)

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
    upload_path = os.path.join(upload_directory, relative_path)

    # creating directories to create the file
    path_with_dirs = os.path.dirname(upload_path)
    os.makedirs(path_with_dirs, exist_ok=True)

    return upload_path


def main():
    load_data()

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(
        r'C:\Users\dmkuz\PycharmProjects\FileSyncApp\FileSync_Server\ssl\syncapp_server.crt',
        r'C:\Users\dmkuz\PycharmProjects\FileSyncApp\FileSync_Server\ssl\syncapp_server.key'
    )

    try:
        app = web.Application(client_max_size=request_max_size)
        app.add_routes(routes)
        web.run_app(app, host=ip, port=port, ssl_context=ssl_context)
    finally:
        save_data()


if __name__ == '__main__':
    main()
