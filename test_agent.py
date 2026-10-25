import sys
import requests
import uuid


def check(name, fn):
    try:
        fn()
        print("PASS", name)
    except Exception as error:
        print("FAIL", name, str(error))
        raise


def health(base):
    response = requests.get(base + "/health", timeout=5)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def invalid_profile(base):
    response = requests.post(
        base + "/v2/incidents",
        json={"profile": "wrong"},
        timeout=5
    )
    assert response.status_code == 422


def missing_run(base):
    response = requests.get(
        base + "/v2/incidents/no-such-run-" + uuid.uuid4().hex,
        timeout=5
    )
    assert response.status_code == 404


def main():
    base = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "http://127.0.0.1:8000"
    ).rstrip("/")

    check("health", lambda: health(base))
    check("unsupported profile rejected", lambda: invalid_profile(base))
    check("unknown run returns 404", lambda: missing_run(base))


if __name__ == "__main__":
    main()
