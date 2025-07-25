from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        print("\n====== Incoming POST Request ======")
        print(f"Path: {self.path}")
        print(f"Headers:\n{self.headers}")
        print("Body:\n", post_data.decode('utf-8'))
        print("===================================")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"POST request received.")

    def do_GET(self):
        print("\n====== Incoming GET Request ======")
        print(f"Path: {self.path}")
        print(f"Headers:\n{self.headers}")
        print("==================================")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        response = "<html><body><h1>Hello, this server accepts GET and POST!</h1></body></html>"
        self.wfile.write(response.encode('utf-8'))


if __name__ == "__main__":
    server_address = ("", 8081)
    httpd = HTTPServer(server_address, SimpleHandler)
    print("Listening on port 8081...")
    httpd.serve_forever()
