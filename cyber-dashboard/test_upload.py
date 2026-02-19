"""Quick test script to verify the upload API works."""
import urllib.request
import json

boundary = "BOUNDARY123"
with open("sample_test.log", "rb") as f:
    file_content = f.read()

body = (
    "--{b}\r\n"
    "Content-Disposition: form-data; name=\"file\"; filename=\"sample_test.log\"\r\n"
    "Content-Type: text/plain\r\n\r\n"
).format(b=boundary).encode() + file_content + ("\r\n--{b}--\r\n".format(b=boundary)).encode()

req = urllib.request.Request(
    "http://127.0.0.1:5000/api/upload",
    data=body,
    headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
    method="POST",
)
resp = urllib.request.urlopen(req)
data = json.loads(resp.read())

print("Success:", data["success"])
print("Total lines:", data["total_lines"])
print("Attacks detected:", data["total_attacks"])
print("Clean lines:", data["clean_lines"])
print("Attack types:", json.dumps(data["attack_summary"], indent=2))
print("Severity:", json.dumps(data["severity_summary"], indent=2))
print("First 3 threats:")
for t in data["threats"][:3]:
    print(f"  Line {t['line_number']}: {t['attack_type']} [{t['severity']}]")
