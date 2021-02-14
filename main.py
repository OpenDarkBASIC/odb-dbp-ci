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
            "port": 8015
        },
        "compilers": [
            {
                "type": "odb",
                "platform": "linux",
                "endpoints": {
                    "update": "http://127.0.0.1:8016/update",
                    "compile": "http://127.0.0.1:8016/compile",
                    "commit_hash": "http://127.0.0.1:8016/commit-hash"
                }
            }
        ],
        "odb-bot": {
            "endpoints": {
                "status": ""
            }
        },
        "github": {
            "ci_sources": {
                "url": "https://www.github.com/OpenDarkBASIC/odb-dbp-ci-sources",
                "secret": ""
            },
            "odbc": {
                "url": "https://www.github.com/OpenDarkBASIC/OpenDarkBASIC",
                "secret": ""
            }
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


def scan_dba_files():
    for root, subdirs, files in os.walk(srcdir):
        for f in files:
            if not f.endswith(".dba"):
                continue
            yield os.path.join(root, f), f


async def pull_and_run_all():
    if not await do_pull_sources():
        return
    await do_run_all()
    await do_status()


async def do_pull_sources():
    async with lock:
        if not os.path.exists(srcdir):
            git_process = await asyncio.create_subprocess_exec("git", "clone", config["github"]["url"], srcdir)
            retval = await git_process.wait()
        else:
            git_process = await asyncio.create_subprocess_exec("git", "pull", cwd=srcdir)
            retval = await git_process.wait()

    async with aiohttp.ClientSession() as session:
        if retval == 0:
            payload = json.dumps({"message": "sources updated"}).encode("utf-8")
            await session.post(url=config["odb-bot"]["endpoints"]["status"], data=payload)
            return True
        else:
            payload = json.dumps({"message": "git command failed"}).encode("utf-8")
            await session.post(url=config["odb-bot"]["endpoints"]["status"], data=payload)
            return False


async def post_status_to_bot(msg):
    try:
        async with aiohttp.ClientSession() as session:
            payload = json.dumps({"message": msg}).encode("utf-8")
            await session.post(url=config["odb-bot"]["endpoints"]["status"], data=payload)
        return True
    except:
        return False


async def do_run_all():
    await post_status_to_bot("CI run started")

    async with lock:
        report = {
            "succeeded": list(),
            "failed": list()
        }
        files_to_compile = list()
        for f, basename in scan_dba_files():

            # Handle invalid file names
            if not any(basename.startswith(x) for x in ("cy-ry-", "cy-rn-", "cn-", "odbc-", "dbpc-")):
                report["failed"].append({
                    "file": f,
                    "message": "Filename is invalid"
                })
                continue

            # Check that corresponding .out files exist
            if any(basename.startswith(x) for x in ("odbc-", "dbpc-")):
                outfile = f.replace(".dba", ".out")
                if not os.path.exists(outfile):
                    report["failed"].append({
                        "file": f,
                        "message": f"Output file {outfile} was not found"
                    })
                    continue
            if basename.startswith("cy-rn-"):
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
            files_to_compile.append((f, basename))

        # Compile the code on all available compilers
        async def do_compile(compiler, filename):
            code_payload = json.dumps({
                "code": open(filename, "rb").read().decode("utf-8")
            }).encode("utf-8")
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url=compiler["endpoints"]["compile"], data=code_payload) as resp:
                        if resp.status != 200:
                            return False, compiler, filename, f"Endpoint for {compiler['type']}-{compiler['platform']} returned {resp.status}"
                        resp = await resp.read()
                        resp = json.loads(resp.decode("utf-8"))
                        return True, compiler, filename, resp
            except:
                return False, compiler, filename, "Failed to connect to endpoint"
        compile_results = await asyncio.gather(*[
            do_compile(compiler, filename)
            for filename, basename in files_to_compile
            for compiler in config["compilers"]])

        # sort compiler results by filename/compiler type/platform
        d = dict()
        for success, compiler, filename, response in compile_results:
            if not success:
                await post_status_to_bot(response)
                return False
            d.setdefault(filename, dict()).setdefault(compiler["type"], dict()).setdefault(compiler["platform"], {
                "success": response["success"],
                "output": response["output"]
            })
        compile_results = d

        for filename, compiler_types in compile_results.items():
            basename = os.path.basename(filename)
            if basename.startswith("cy-"):
                if not all(result["success"]
                           for compiler_type, compiler_plats in compiler_types.items()
                           for compiler_plat, result in compiler_plats.items()):
                    failed_names = [f"{compiler_type}/{compiler_plat}"
                                    for compiler_type, compiler_plats in compiler_types.items()
                                    for compiler_plat, result in compiler_plats.items()
                                    if not result["success"]]
                    failed_msgs = [f"{compiler_type}/{compiler_plat}: {result['output']}"
                                   for compiler_type, compiler_plats in compiler_types.items()
                                   for compiler_plat, result in compiler_plats.items()
                                   if not result["success"]]
                    report["failed"].append({
                        "file": f,
                        "message": f"Code failed to compile for targets: {', '.join(failed_names)}\n" + "\n".join(failed_msgs)
                    })
                    continue

            # If we reach this point and the file begins with "cy-" then it did compile successfully

            if basename.startswith("cy-ry-"):
                if not all_equal(result["output"] for compiler_type, compiler_plats in compiler_types.items() for compiler_plat, result in compiler_plats.items()):
                    outputs = [f"{compiler_type}/{compiler_plat}: {result['output']}"
                               for compiler_type, compiler_plats in compiler_types.items()
                               for compiler_plat, result in compiler_plats.items()]
                    report["failed"].append({
                        "file": f,
                        "message": f"Output is different between targets\n" + "\n".join(outputs)
                    })
                    continue
                report["succeeded"].append({
                    "file": f
                })
            elif basename.startswith("cy-rn-"):
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
            elif basename.startswith("cn-"):
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
            elif basename.startswith("odbc-"):
                pass
            elif basename.startswith("dbpc-"):
                pass
            else:
                report["failed"].append({
                    "file": f,
                    "message": "BUG: Unknown/unsupported filename"
                })
    open(os.path.join(workdir, "report.json"), "wb").write(json.dumps(report).encode("utf-8"))
    await post_status_to_bot("CI run completed")
    return True


async def do_status():
    async with lock:
        pass


@app.route("/ci-sources-push", methods=["POST"])
async def github_event_ci_sources_pushed():
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

    asyncio.ensure_future(pull_and_run_all())
    return "", 200


@app.route("/odbc-push", methods=["POST"])
async def github_event_odb_pushed():
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

    return "", 200


@app.route("/pull-sources")
async def pull_sources():
    await do_pull_sources()
    return "", 200


@app.route("/run-all")
async def run_all():
    await do_run_all()
    return "", 200


@app.route("/status")
async def status():
    await do_status()
    return "", 200


loop = asyncio.get_event_loop()
try:
    app.run(loop=loop, host=config["server"]["host"], port=config["server"]["port"])
except:
    traceback.print_exc()
finally:
    loop.close()
