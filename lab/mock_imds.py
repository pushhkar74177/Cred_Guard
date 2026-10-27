#!/usr/bin/env python3
"""Mock AWS Instance Metadata Service (IMDSv1 enabled) for the CredGuard demo.

Listens on 169.254.169.254:80 exactly like the real IMDS on an EC2 instance.
Every value it returns is FAKE demo data; nothing here is a real AWS credential.
"""
import json
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

INSTANCE_ID = "i-0c4a1d2e3f4demo"
ROLE_NAME = "credguard-demo-role"
ACCOUNT_ID = "111122223333"  # AWS documentation example account


def fake_credentials():
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "Code": "Success",
        "LastUpdated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Type": "AWS-HMAC",
        "AccessKeyId": "ASIAFAKEDEMOKEY00001",
        "SecretAccessKey": "fake/DEMO/secret/not+a+real+key/credguard",
        "Token": "FAKE-SESSION-TOKEN-FOR-CREDGUARD-DEMO",
        "Expiration": (now + datetime.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


ROUTES = {
    "/latest/meta-data/": "ami-id\nhostname\ninstance-id\nlocal-ipv4\niam/\n",
    "/latest/meta-data/instance-id": INSTANCE_ID,
    "/latest/meta-data/ami-id": "ami-0demo1234567890",
    "/latest/meta-data/hostname": "ip-10-0-1-25.ec2.internal",
    "/latest/meta-data/local-ipv4": "10.0.1.25",
    "/latest/meta-data/iam/": "info\nsecurity-credentials/\n",
    "/latest/meta-data/iam/info": json.dumps({
        "Code": "Success",
        "InstanceProfileArn": f"arn:aws:iam::{ACCOUNT_ID}:instance-profile/{ROLE_NAME}",
    }),
    "/latest/meta-data/iam/security-credentials/": ROLE_NAME,
}


class IMDSHandler(BaseHTTPRequestHandler):
    server_version = "EC2ws"
    sys_version = ""

    def _reply(self, code, body, ctype="text/plain"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == f"/latest/meta-data/iam/security-credentials/{ROLE_NAME}":
            return self._reply(200, json.dumps(fake_credentials(), indent=2), "application/json")
        if path in ROUTES:
            return self._reply(200, ROUTES[path])
        return self._reply(404, "Not Found")

    def do_PUT(self):
        # IMDSv2 session token endpoint (IMDSv1 is still enabled, so tokens are optional)
        if self.path == "/latest/api/token":
            return self._reply(200, "FAKE-IMDSV2-TOKEN")
        return self._reply(404, "Not Found")

    def log_message(self, fmt, *args):
        print("[mock-imds] %s - %s" % (self.client_address[0], fmt % args), flush=True)


if __name__ == "__main__":
    print("[mock-imds] listening on http://169.254.169.254:80 (IMDSv1 enabled)", flush=True)
    HTTPServer(("169.254.169.254", 80), IMDSHandler).serve_forever()
