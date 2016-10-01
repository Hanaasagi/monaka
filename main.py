# -*-coding:UTF-8 -*-
import os
import stat
import sys
import qrcode
import socket
import re
import fcntl
import struct
import argparse
import webbrowser
import tornado.gen
import tornado.httpserver
import tornado.ioloop
import tornado.web
from tornado import iostream

file_path = ''
port = 10053


class DownloadHandler(tornado.web.RequestHandler):

    @tornado.gen.coroutine
    def get(self):
        file_name = file_path.split('/')[-1]
        content_length = self.get_content_size(file_path)
        start, end = 0, content_length
        header_range = self.request.headers.get('Range', '')
        info = re.findall('bytes=([\d]+)-([\d]*)', header_range)
        if info:
            start = int(info[0][0])
            end = int(info[0][1])

        if start > 0 or end < content_length:
            self.set_status(206)
            self.set_header(
                'Content-Range', 'bytes {0}-{1}/{2}'.format(start, end, content_length))
        else:
            self.set_status(200)
        # common headers
        self.set_header("Content-Length", end - start)
        self.set_header("Content-Type", "application/octet-stream")
        self.set_header("Content-Disposition",
                        "attachment;filename=\"{0}\"".format(file_name))
        content = self.get_content(file_path, start, end)
        if isinstance(content, bytes):
            content = [content]
        for chunk in content:
            try:
                self.write(chunk)
                yield self.flush()
            except iostream.StreamClosedError:
                break
        return

    def get_content(self, file_path, start=None, end=None):
        with open(file_path, "rb") as file:
            if start is not None:
                file.seek(start)
            if end is not None:
                remaining = end - (start or 0)
            else:
                remaining = None
            while True:
                chunk_size = 64 * 1024
                if remaining is not None and remaining < chunk_size:
                    chunk_size = remaining
                chunk = file.read(chunk_size)
                if chunk:
                    if remaining is not None:
                        remaining -= len(chunk)
                    yield chunk
                else:
                    if remaining is not None:
                        assert remaining == 0
                    return

    def get_content_size(self, file_path):
        stat_result = os.stat(file_path)
        content_size = stat_result[stat.ST_SIZE]
        return content_size


class DefaultHandler(tornado.web.RequestHandler):

    def get(self):
        self.render('index.html')


class Application(tornado.web.Application):

    def __init__(self):
        handlers = [
            (r"/download", DownloadHandler),
            (r".*?", DefaultHandler),
        ]
        static_path = os.path.join(os.path.dirname(__file__), "static")
        tornado.web.Application.__init__(
            self, handlers=handlers, static_path=static_path)


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def create_qr(ip, port):
    qr = qrcode.make('http://{0}:{1}/download'.format(ip, port))
    qr.save('./static/qr.png')


def cmd_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument('-p', type=str, dest='file_path', required=True,
                        action='store', help='Specify your download path')
    parser.add_argument('-i', type=str, dest='interface', required=True,
                        action='store', help='interface wlan0 or eth0 ...')
    args = parser.parse_args()
    return args.file_path, args.interface


if __name__ == "__main__":
    file_path, interface = cmd_parser()
    ip = get_ip_address(interface)
    create_qr(ip, port)
    webbrowser.open_new('http://127.0.0.1:{}'.format(port))
    application = Application()
    http_server = tornado.httpserver.HTTPServer(application, xheaders=True)
    http_server.listen(port)
    print('Listen on http://localhost:{0}'.format(port))
    tornado.ioloop.IOLoop.instance().start()
