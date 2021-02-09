import quart
import os
import json
import asyncio
import traceback
import hashlib
import hmac
import aiohttp


if not os.path.exists("config.json"):
    open("config.json", "wb").write(json.dumps({
        "server": {
            "host": "0.0.0.0",
            "port": 8080
        },
        "odbc": {
            "windows": {
                "url": ""
            },
            "linux": {
                "url": ""
            }
        },
        "dbpc": {
            "url": ""
        },
        "odb-bot": {
            "url": ""
        },
        "github": {
            "url": "https://www.github.com/OpenDarkBASIC/odb-dbp-ci-sources",
            "secret": ""
        }
    }, indent=2).encode("utf-8"))
    print("Created file config.json. Please edit it with the correct token now, then run the bot again")
    import sys
    sys.exit(1)


config = json.loads(open("config.json", "rb").read().decode("utf-8"))
app = quart.Quart(__name__)
lock = asyncio.Lock()

cachedir = "cache"
srcdir = os.path.join(cachedir, "sources")
workdir = os.path.join(cachedir, "work")

if not os.path.exists(cachedir):
    os.mkdir(cachedir)
if not os.path.exists(workdir):
    os.mkdir(workdir)


def verify_signature(payload, signature, secret):
    payload_signature = hmac.new(
            key=secret.encode("utf-8"),
            msg=payload,
            digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(payload_signature, signature)


def create_signature(payload, secret):
    payload_signature = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256).hexdigest()
    return payload_signature


def all_equal(l):
    iterator = iter(l)
    try:
        first = next(l)
    except StopIteration:
        return True
    return all(first == rest for rest in iterator)


async def update_and_run_all():
    s, status = await update_sources()
    if status != 200:
        return
    await run_all()


@app.route("/github", methods=["POST"])
async def github_event():
    payload = await quart.request.get_data()
    if not verify_signature(payload, quart.request.headers["X-Hub-Signature-256"].replace("sha256=", ""), config["github"]["secret"]):
        quart.abort(403)

    event_type = quart.request.headers["X-GitHub-Event"]
    if not event_type == "push":
        return "", 200

    # only care about pushes to master branch
    data = json.loads(payload.decode("utf-8"))
    if not data["ref"].rsplit("/", 1)[-1] == "master":
        return ""

    asyncio.ensure_future(update_and_run_all())
    return "", 200


@app.route("/update_sources")
async def update_sources():
    async with lock:
        if not os.path.exists(srcdir):
            git_process = await asyncio.create_subprocess_exec("git", "clone", config["github"]["url"], srcdir)
            retval = await git_process.wait()
        else:
            git_process = await asyncio.create_subprocess_exec("git", "pull", cwd=srcdir)
            retval = await git_process.wait()

    if retval != 0:
        payload = json.dumps({"message": "git command failed"}).encode("utf-8")
        with aiohttp.clientSession() as session:
            async with session.post(url=config["odb-bot"]["url"] + "/odb-dbp-ci/status", data=payload) as resp:
                return "", resp.status


def iterate_dba_files():
    for root, subdirs, files in os.walk(srcdir):
        for f in files:
            if not f.endswith(".dba"):
                continue
            yield os.path.join(root, f)


@app.route("/run_all")
async def run_all():
    async with lock:
        with aiohttp.clientSession() as session:
            report = {
                "succeeded": list(),
                "failed": list()
            }
            for f in iterate_dba_files():

                # Handle invalid file names
                if not any(f.startswith(x) for x in ("cy-ry-", "cy-rn-", "cn-", "odbc-", "dbpc-")):
                    report["failed"].append({
                        "file": f,
                        "message": "Filename is invalid"
                    })
                    continue

                # Check that corresponding .out files exist
                if any(f.startswith(x) for x in ("odbc-", "dbpc-")):
                    outfile = f.replace(".dba", ".out")
                    if not os.path.exists(outfile):
                        report["failed"].append({
                            "file": f,
                            "message": f"Output file {outfile} was not found"
                        })
                        continue
                if f.startswith("cy-rn-"):
                    outfile1 = f.replace(".dba", ".dbpout")
                    outfile2 = f.replace(".dba", ".odbout")
                    if not os.path.exists(outfile1):
                        report["failed"].append({
                            "file": f,
                            "message": f"Output file {outfile1} was not found"
                        })
                        continue
                    if not os.path.exists(outfile2):
                        report["failed"].append({
                            "file": f,
                            "message": f"Output file {outfile2} was not found"
                        })
                        continue

                # Compile the code on all available compilers
                code_payload = json.dumps({
                    "code": open(f, "rb").read().decode("utf-8")
                })
                async with session.post(url=config["dbpc"]["endpoints"]["compile"], data=code_payload) as dbpc_resp:
                    if dbpc_resp.status != 200:
                        bot_payload = json.dumps(
                            {"message": f"dbpc endpoint returned status {dbpc_resp.status}"}).encode("utf-8")
                        await session.post(url=config["odb-bot"]["endpoints"]["status"], data=bot_payload)
                        return "", dbpc_resp.status
                    dbpc_resp = await dbpc_resp.read()
                    dbpc_resp = json.loads(dbpc_resp.decode("utf-8"))
                async with session.post(url=config["odbc"]["windows"]["endpoints"]["compile"],
                                        data=code_payload) as odbc_windows_resp:
                    if odbc_windows_resp.status != 200:
                        bot_payload = json.dumps(
                            {"message": f"odbc windows endpoint returned status {odbc_windows_resp.status}"}).encode(
                            "utf-8")
                        await session.post(url=config["odb-bot"]["endpoints"]["status"], data=bot_payload)
                        return "", odbc_windows_resp.status
                    odbc_windows_resp = await odbc_windows_resp.read()
                    odbc_windows_resp = json.loads(odbc_windows_resp.decode("utf-8"))
                async with session.post(url=config["odbc"]["windows"]["endpoints"]["compile"],
                                        data=code_payload) as odbc_linux_resp:
                    if odbc_linux_resp.status != 200:
                        bot_payload = json.dumps(
                            {"message": f"odbc linux endpoint returned status {odbc_linux_resp.status}"}).encode(
                            "utf-8")
                        await session.post(url=config["odb-bot"]["endpoints"]["status"], data=bot_payload)
                        return "", odbc_linux_resp.status
                    odbc_linux_resp = await odbc_linux_resp.read()
                    odbc_linux_resp = json.loads(odbc_linux_resp.decode("utf-8"))

                # put the results into a list and add some more data to make it easier to work with
                dbpc_resp["name"] = "dbpc"
                odbc_windows_resp["name"] = "odbc-windows"
                odbc_linux_resp["name"] = "odbc-linux"
                results = (dbpc_resp, odbc_windows_resp, odbc_linux_resp)

                if f.startswith("cy-"):
                    if not all(x["success"] for x in results):
                        failed_names = [x["name"] for x in results if not x["success"]]
                        failed_msgs = [f"{x['name']}: {x['output']}" for x in results if not x["success"]]
                        report["failed"].append({
                            "file": f,
                            "message": f"Code failed to compile for targets: {', '.join(failed_names)}\n" + "\n".join(failed_msgs)
                        })
                        continue
                if f.startswith("cy-ry-"):
                    if not all_equal(x["output"] for x in results):
                        outputs = [f"{x['name']}: {x['output']}" for x in results]
                        report["failed"].append({
                            "file": f,
                            "message": f"Output is different between targets\n" + "\n".join(outputs)
                        })
                        continue
                    report["succeeded"].append({
                        "file": f
                    })
                elif f.startswith("cy-rn-"):
                    if all_equal(x["output"] for x in results):
                        outputs = [f"{x['name']}: {x['output']}" for x in results]
                        report["failed"].append({
                            "file": f,
                            "message": "Output was identical for all targets, but it was expected to be different\n" + "\n".join(outputs)
                        })
                        continue
                    for result in results:
                        if result["name"] == "dbpc":
                            expected = open(f.replace(".dba", ".dbpout"), "rb").read().decode("utf-8")
                        elif result["name"] in ("odbc-windows", "odbc-linux"):
                            expected = open(f.replace(".dba", ".odbout"), "rb").read().decode("utf-8")
                        if not result["output"] == expected:
                            report["failed"].append({
                                "file": f,
                                "message": f"{result['name']}: Expected output: {expected}\nActual output: {result['output']}"
                            })
                            continue
                        if not result["output"] == expected:
                            report["failed"].append({
                                "file": f,
                                "message": f"{result['name']}: Expected output: {expected}\nActual output: {result['output']}"
                            })
                            continue
                    report["succeeded"].append({
                        "file": f
                    })
                elif f.startswith("cn-"):
                    if any(x["success"] for x in results):
                        failed_names = [x["name"] for x in results if x["success"]]
                        report["failed"].append({
                            "file": f,
                            "message": f"Code compiled for targets: {', '.join(failed_names)}\n"
                        })
                        continue
                    report["succeeded"].append({
                        "file": f
                    })
                elif f.startswith("odbc-"):
                    pass
                elif f.startswith("dbpc-"):
                    pass
                else:
                    report["failed"].append({
                        "file": f,
                        "message": "BUG: Unknown/unsupported filename"
                    })

    return "", 200


@app.route("/status")
async def status():
    pass


loop = asyncio.get_event_loop()
try:
    app.run(loop=loop, host=config["server"]["host"], port=config["server"]["port"])
except:
    traceback.print_exc()
finally:
    loop.close()
