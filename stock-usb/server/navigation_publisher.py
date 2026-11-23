"""Operator-only navigation publisher. Run behind an HTTPS reverse proxy."""
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import subprocess
import tempfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


REPO = "go1sk1/CarrotCast"
TAG = "external-navigation"
CATALOG = "updates/lite/navigation-managed.json"
APPS = {"com.skt.tmap.ku": "tmap", "com.nhn.android.nmap": "naver"}
RELAY = "bdfb9d47baf7c9e5d2ab3ed067b57bc9b2efbeccd67d6a88f9130374e83a585e"
MAX_BYTES = 256 * 1024 * 1024
PUBLISH_LOCK = threading.Lock()


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise ValueError("APK 검사 도구가 파일을 거부했습니다.")
    return result.stdout


def inspect(path, approved):
    report = command(os.environ.get("JAVA", "java"), "-jar", os.environ["APKSIGNER_JAR"],
                     "verify", "--min-sdk-version", "30", "--print-certs", str(path))
    signers = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([a-f0-9]{64})", report)
    if len(signers) != 1 or signers[0] not in approved:
        raise ValueError("등록된 배포용 미러폰의 서명과 일치하지 않습니다.")
    aapt = os.environ["AAPT"]
    badging = command(aapt, "dump", "badging", str(path))
    match = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'[^\r\n]*", badging, re.M)
    if not match:
        raise ValueError("패키지 정보를 읽을 수 없습니다.")
    package, code, version = match.groups()
    if package not in APPS or not 0 < int(code) <= 2147483647 or not re.fullmatch(r"[0-9]{1,6}(\.[0-9]{1,6}){1,4}", version):
        raise ValueError("지원하지 않는 내비 패키지 또는 버전입니다.")
    manifest = command(aapt, "dump", "xmltree", str(path), "AndroidManifest.xml")
    if re.search(r"(?m)^\s*(?:A: (?:android:)?(?:split|isSplitRequired|requiredSplitTypes|splitTypes|isFeatureSplit)(?:[=(])|E: uses-split\b)", manifest):
        raise ValueError("단일 APK만 배포할 수 있습니다.")
    with zipfile.ZipFile(path) as apk:
        names = apk.namelist()
        if len(names) != len(set(names)):
            raise ValueError("APK에 중복 항목이 있습니다.")
        marker = apk.getinfo("assets/carrotcast-comma.json")
        if marker.file_size > 65536:
            raise ValueError("APK 모듈 정보가 너무 큽니다.")
        info = json.loads(apk.read(marker))
        dex = info.get("payload_dex", "")
        if (info.get("package") != package or info.get("version_code") != int(code)
                or info.get("relay_target") != "dev.carrotcast.stockusb.atc" or info.get("payload_sha256") != RELAY
                or not re.fullmatch(r"classes([2-9]|[1-9][0-9]+)\.dex", dex)
                or apk.getinfo(dex).file_size > 4 * 1024 * 1024
                or hashlib.sha256(apk.read(dex)).hexdigest() != RELAY):
            raise ValueError("Lite 통신 모듈을 검증하지 못했습니다.")
    return dict(package=package, version_code=int(code), version_name=version,
                bytes=path.stat().st_size, sha256=sha(path), signer=signers[0])


def github(method, route, *, body=None, asset=None, missing=False):
    host = "uploads.github.com" if asset else "api.github.com"
    connection = http.client.HTTPSConnection(host, timeout=90)
    headers = {"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
               "User-Agent": "CarrotCast-Navigation-Publisher", "Accept": "application/vnd.github+json"}
    try:
        if asset:
            headers.update({"Content-Type": "application/vnd.android.package-archive",
                            "Content-Length": str(asset.stat().st_size)})
            with asset.open("rb") as stream:
                connection.request(method, f"/repos/{REPO}/{route}", stream, headers)
        else:
            if body is not None:
                body = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            connection.request(method, f"/repos/{REPO}/{route}", body, headers)
        response = connection.getresponse()
        data = response.read(2 * 1024 * 1024)
        if missing and response.status == 404:
            return None
        if not 200 <= response.status < 300:
            raise RuntimeError(f"GitHub HTTP {response.status}")
        return json.loads(data)
    finally:
        connection.close()


def catalog(key):
    current = github("GET", "contents/" + CATALOG + "?ref=main", missing=True)
    if current is None:
        return None, dict(schema=1, product="CarrotCast-managed-navigation", apps={})
    envelope = json.loads(base64.b64decode(current["content"]))
    payload = base64.b64decode(envelope["payload"], validate=True)
    key.public_key().verify(base64.b64decode(envelope["signature"], validate=True),
                            payload, padding.PKCS1v15(), hashes.SHA256())
    feed = json.loads(payload)
    if feed.get("schema") != 1 or feed.get("product") != "CarrotCast-managed-navigation":
        raise RuntimeError("배포 목록 형식 오류")
    return current["sha"], feed


def publish(path, row, key):
    app = APPS[row["package"]]
    name = f"{app}-{row['version_code']}-{row['sha256']}.apk"
    with PUBLISH_LOCK:
        blob, feed = catalog(key)
        previous = feed["apps"].get(app)
        legacy_file = github("GET", "contents/updates/lite/navigation.json?ref=main")
        legacy = json.loads(base64.b64decode(legacy_file["content"]))[app]
        if row["version_code"] < max(legacy["version_code"], previous["version_code"] if previous else 0):
            raise ValueError("이미 배포된 버전보다 오래된 APK입니다.")
        if previous and previous["signer"] != row["signer"]:
            raise ValueError("이 내비의 기존 관리형 배포 서명과 다릅니다.")
        if previous and previous["version_code"] == row["version_code"] and previous != row:
            raise ValueError("이 버전 번호에 다른 APK가 이미 배포되어 있습니다.")
        release = github("GET", "releases/tags/" + TAG)
        if release["tag_name"] != TAG or release["draft"]:
            raise RuntimeError("외부 내비 릴리스가 공개 상태가 아닙니다.")
        release_id = int(release["id"])
        assets = release["assets"]
        if len(assets) >= 30:
            assets = []
            for page in range(1, 12):
                batch = github("GET", f"releases/{release_id}/assets?per_page=100&page={page}")
                assets.extend(batch)
                if len(batch) < 100:
                    break
        asset = next((item for item in assets if item["name"] == name), None)
        if asset is None:
            asset = github("POST", f"releases/{release_id}/assets?name={quote(name)}", asset=path)
        if (asset["state"] != "uploaded" or asset["size"] != row["bytes"]
                or asset.get("digest") != "sha256:" + row["sha256"]):
            raise RuntimeError("GitHub 업로드 검증 실패")
        if previous != row:
            feed["apps"][app] = row
            payload = json.dumps(feed, sort_keys=True, separators=(",", ":")).encode()
            sig = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
            envelope = json.dumps(dict(payload=base64.b64encode(payload).decode(), signature=base64.b64encode(sig).decode()))
            body = dict(branch="main", message=f"Publish {app} {row['version_name']} navigation APK",
                        content=base64.b64encode(envelope.encode()).decode())
            if blob:
                body["sha"] = blob
            github("PUT", "contents/" + CATALOG, body=body)
        _, confirmed = catalog(key)
        if confirmed["apps"].get(app) != row:
            raise RuntimeError("배포 목록 읽기 검증 실패")
        return {"ok": True, "version": row["version_name"]}


def publish_draft(draft_id, asset_id):
    if not all(re.fullmatch(r"[1-9][0-9]{0,18}", value) for value in (draft_id, asset_id)):
        raise ValueError("Invalid draft release or asset identifier")
    draft = github("GET", f"releases/{draft_id}")
    if not draft["draft"] or not re.fullmatch(r"navigation-inbox-[a-f0-9]{64}", draft["tag_name"]):
        raise ValueError("Only navigation intake drafts can be published")
    asset = next((item for item in draft["assets"] if str(item["id"]) == asset_id), None)
    if (asset is None or asset["name"] != "navigation.apk" or asset["state"] != "uploaded"
            or not 0 < asset["size"] <= MAX_BYTES):
        raise ValueError("Invalid navigation intake asset")
    connection = http.client.HTTPSConnection("api.github.com", timeout=90)
    download = None
    try:
        connection.request("GET", f"/repos/{REPO}/releases/assets/{asset_id}", headers={
            "Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
            "User-Agent": "CarrotCast-Navigation-Publisher", "Accept": "application/octet-stream"})
        response = connection.getresponse()
        if response.status in (301, 302, 303, 307, 308):
            location = urlsplit(response.getheader("Location", ""))
            if (location.scheme != "https" or not location.hostname or location.username or location.port
                    or not (location.hostname == "release-assets.githubusercontent.com"
                            or location.hostname == "objects.githubusercontent.com")):
                raise ValueError("Unexpected GitHub download host")
            download = http.client.HTTPSConnection(location.hostname, timeout=90)
            download.request("GET", location.path + ("?" + location.query if location.query else ""))
            response = download.getresponse()
        if response.status != 200:
            raise RuntimeError(f"GitHub draft download failed: HTTP {response.status}")
        with tempfile.TemporaryDirectory() as work:
            apk = Path(work) / "navigation.apk"
            remaining = asset["size"]
            with apk.open("wb") as out:
                while remaining:
                    chunk = response.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Incomplete draft download")
                    remaining -= len(chunk)
                    out.write(chunk)
                if response.read(1):
                    raise ValueError("Unexpected asset size")
            digest = sha(apk)
            if asset.get("digest") != "sha256:" + digest or draft["tag_name"] != "navigation-inbox-" + digest:
                raise ValueError("Draft digest mismatch")
            key = serialization.load_pem_private_key(os.environ["CATALOG_SIGNING_PEM"].encode(), None)
            check_catalog_key(key)
            approved = set(os.environ["PUBLISH_APK_SIGNERS"].lower().split(","))
            result = publish(apk, inspect(apk, approved), key)
            print("Published managed navigation", result["version"])
    finally:
        connection.close()
        if download:
            download.close()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(60)
        super().setup()

    def reply(self, status, value):
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/publish":
            return self.reply(404, {"error": "잘못된 배포 주소"})
        if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), self.server.authorization):
            return self.reply(401, {"error": "배포 인증이 필요합니다."})
        try:
            remaining = int(self.headers.get("Content-Length", "0"))
            if not 0 < remaining <= MAX_BYTES or self.headers.get("Transfer-Encoding"):
                raise ValueError("지원하지 않는 APK 크기입니다.")
            with tempfile.TemporaryDirectory() as work:
                apk = Path(work) / "upload.apk"
                with apk.open("wb") as output:
                    while remaining:
                        data = self.rfile.read(min(remaining, 1024 * 1024))
                        if not data:
                            raise ValueError("업로드가 끝나기 전에 연결이 끊겼습니다.")
                        output.write(data)
                        remaining -= len(data)
                result = publish(apk, inspect(apk, self.server.approved), self.server.key)
            self.reply(200, result)
        except (ValueError, KeyError, zipfile.BadZipFile):
            self.reply(422, {"error": "APK 검증 실패 또는 배포 조건 불일치"})
        except Exception as error:
            self.log_error("Publisher failure: %s", type(error).__name__)
            self.reply(502, {"error": "배포를 완료하지 못했습니다. APK를 다시 요청해도 중복 배포되지 않습니다."})


def main():
    operator = os.environ["PUBLISH_OPERATOR_TOKEN"]
    approved = set(os.environ["PUBLISH_APK_SIGNERS"].lower().split(","))
    if len(operator) < 32 or not all(re.fullmatch(r"[a-f0-9]{64}", x) for x in approved):
        raise ValueError("Configure the operator token and approved APK signing fingerprints")
    for needed in ("AAPT", "APKSIGNER_JAR", "GITHUB_TOKEN"):
        if not os.environ.get(needed):
            raise ValueError(f"Missing server setting: {needed}")
    key = serialization.load_pem_private_key(Path(os.environ["CATALOG_SIGNING_KEY"]).read_bytes(), None)
    check_catalog_key(key)
    server = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "8751"))), Handler)
    server.authorization = ("Bearer " + operator).encode()
    server.approved = approved
    server.key = key
    server.serve_forever()


def check_catalog_key(key):
    approved = base64.b64decode(Path(os.environ["CATALOG_PUBLIC_KEY"]).read_bytes().strip(), validate=True)
    actual = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if not hmac.compare_digest(actual, approved):
        raise ValueError("Catalog private key does not match the public key shipped in Lite")


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 4 and sys.argv[1] == "draft":
        publish_draft(*sys.argv[2:])
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit("Usage: navigation_publisher.py [draft RELEASE_ID ASSET_ID]")
