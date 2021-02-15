import quart
import os
import json
import asyncio
import traceback
import hashlib
import hmac
import aiohttp
import re


if not os.path.exists("config.json"):
    open("config.json", "wb").write(json.dumps({
        "server": {
            "host": "0.0.0.0",
            "port": 8016
        },
        "compilers": [
            {
                "type": "dbp",
                "platform": "windows",
                "endpoints": {
                    "update": "http://127.0.0.1:8014/update",
                    "compile_multi": "http://127.0.0.1:8014/compile_multi",
                    "commit_hash": "http://127.0.0.1:8014/commit_hash"
                },
            },
            {
                "type": "odb",
                "platform": "linux",
                "endpoints": {
                    "update": "http://127.0.0.1:8014/update",
                    "compile_multi": "http://127.0.0.1:8014/compile_multi",
                    "commit_hash": "http://127.0.0.1:8014/commit_hash"
                }
            }
        ],
        "odb-bot": {
            "endpoints": {
                "status": ""
            }
        },
        "git": {
            "command": "git"
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
        first = next(iterator)
    except StopIteration:
        return True
    return all(first == rest for rest in iterator)


def scan_dba_files():
    for root, subdirs, files in os.walk(srcdir):
        for f in files:
            if not f.endswith(".dba"):
                continue
            yield os.path.join(root, f), f


def load_outfile(outfile):
    expected = open(outfile, "rb").read().decode("utf-8")
    match = re.match(r"\"(.*)\"", expected)
    if not match:
        return None
    return match.group(1).replace("\\n", "\n")


async def pull_and_run_all():
    if not await do_pull_sources():
        return
    await do_run_all()
    await do_status()


async def do_pull_sources():
    async with lock:
        if not os.path.exists(srcdir):
            git_process = await asyncio.create_subprocess_exec(config["git"]["command"], "clone", config["github"]["ci_sources"]["url"], srcdir)
            retval = await git_process.wait()
        else:
            git_process = await asyncio.create_subprocess_exec(config["git"]["command"], "pull", cwd=srcdir)
            retval = await git_process.wait()

    if retval == 0:
        return True, ""
    else:
        return False, "git command failed"


async def post_status_to_bot(msg):
    try:
        async with aiohttp.ClientSession() as session:
            payload = json.dumps({"message": msg}).encode("utf-8")
            await session.post(url=config["odb-bot"]["endpoints"]["status"], data=payload)
        return True
    except:
        return False


async def do_run_all():
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
        async def do_compile(compiler, file_list):
            code_list = (open(filename, "rb").read().decode("utf-8") for filename in file_list)
            code_payloads = [{"code": code} for code in code_list]
            payload = json.dumps(code_payloads).encode("utf-8")
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url=compiler["endpoints"]["compile_multi"], data=payload) as resp:
                        if resp.status != 200:
                            return False, compiler, f"Endpoint for {compiler['type']}-{compiler['platform']} returned {resp.status}"
                        resp = await resp.read()
                        resp = json.loads(resp.decode("utf-8"))
                        return True, compiler, resp
            except:
                return False, compiler, "Failed to connect to endpoint"
        compile_results = await asyncio.gather(*[
            do_compile(compiler, [filename for filename, basename in files_to_compile])
            for compiler in config["compilers"]])

        # sort compiler results by filename/compiler type/platform
        d = dict()
        for success, compiler, response in compile_results:
            if not success:
                await post_status_to_bot(response)
                return False
            for filename, basename, single_response in (list(fb)+[r] for fb, r in zip(files_to_compile, response)):
                d.setdefault(filename, dict()).setdefault(compiler["type"], dict()).setdefault(compiler["platform"], {
                    "success": single_response["success"],
                    "output": single_response["output"]
                })
        compile_results = d

        for filename, compiler_types in compile_results.items():
            basename = os.path.basename(filename)

            # first of all, make sure that all ODB outputs are identical and all DBP outputs are identical. The same
            # compiler on different platforms should always behave the same
            if any(basename.startswith(x) for x in ("cy-", "dbpc-")):
                if not all(result["success"] for compiler_plat, result in compiler_types["dbp"].items()):
                    failed_names = [f"dbp/{compiler_plat}"
                                    for compiler_plat, result in compiler_types["dbp"].items()
                                    if not result["success"]]
                    failed_msgs = [f"dbp/{compiler_plat}: {result['output']}"
                                   for compiler_plat, result in compiler_types["dbp"].items()
                                   if not result["success"]]
                    report["failed"].append({
                        "file": filename,
                        "message": f"Code failed to compile for targets: {', '.join(failed_names)}\n" + "\n".join(failed_msgs)
                    })
                    continue

                dbp_outputs = [result["output"] for compiler_plat, result in compiler_types["dbp"].items()]
                if not all_equal(dbp_outputs):
                    dbp_msgs = [f"dbp/{compiler_plat}: {result['output']}"
                                for compiler_plat, result in compiler_types["dbp"].items()]
                    report["failed"].append({
                        "file": filename,
                        "message": "Not all DBP outputs were the same!\n" + "\n".join(dbp_msgs)
                    })
                    continue
                dbp_output = dbp_outputs[0]

            if any(basename.startswith(x) for x in ("cy-", "odbc-")):
                if not all(result["success"] for compiler_plat, result in compiler_types["odb"].items()):
                    failed_names = [f"odb/{compiler_plat}"
                                    for compiler_plat, result in compiler_types["odb"].items()
                                    if not result["success"]]
                    failed_msgs = [f"odb/{compiler_plat}: {result['output']}"
                                   for compiler_plat, result in compiler_types["odb"].items()
                                   if not result["success"]]
                    report["failed"].append({
                        "file": filename,
                        "message": f"Code failed to compile for targets: {', '.join(failed_names)}\n" + "\n".join(failed_msgs)
                    })
                    continue

                odb_outputs = [result["output"] for compiler_plat, result in compiler_types["odb"].items()]
                if not all_equal(odb_outputs):
                    odb_msgs = [f"odb/{compiler_plat}: {result['output']}"
                                for compiler_plat, result in compiler_types["odb"].items()]
                    report["failed"].append({
                        "file": filename,
                        "message": "Not all DBP outputs were the same!\n" + "\n".join(odb_msgs)
                    })
                    continue
                odb_output = odb_outputs[0]

            # If we reach this point and the file begins with "cy-", "odbc-", or "dbpc-",
            # then it did compile successfully

            if basename.startswith("cy-ry-"):
                if not dbp_output == odb_output:
                    report["failed"].append({
                        "file": filename,
                        "message": f"Output is different between targets\nODB: {odb_output}\nDBP: {dbp_output}"
                    })
                    continue

                # The .out file is optional, but if it exists, make sure the output is correct
                outfile = filename.replace(".dba", ".out")
                if os.path.exists(outfile):
                    expected = load_outfile(outfile)
                    if expected is None:
                        report["failed"].append({
                            "file": filename,
                            "message": f"Outfile contains invalid data/is incorrectly formatted"
                        })
                        continue
                    if not dbp_output == expected:
                        report["failed"].append({
                            "file": filename,
                            "message": f"Output is different from expected .out file\nExpected: {expected}\nActual: {dbp_output}"
                        })
                        continue
                    if not odb_output == expected:
                        report["failed"].append({
                            "file": filename,
                            "message": f"Output is different from expected .out file\nExpected: {expected}\nActual: {odb_output}"
                        })
                        continue

                report["succeeded"].append({
                    "file": filename
                })

            elif basename.startswith("cy-rn-"):
                if dbp_output == odb_output:
                    report["failed"].append({
                        "file": filename,
                        "message": f"Output was identical on all targets, but it was expected to be different\nODB: {odb_output}\nDBP: {dbp_output}"
                    })
                    continue

                dbp_expected = open(filename.replace(".dba", ".dbpout"), "rb").read().decode("utf-8")
                odb_expected = open(filename.replace(".dba", ".odbout"), "rb").read().decode("utf-8")
                if not dbp_output == dbp_expected:
                    report["failed"].append({
                        "file": filename,
                        "message": f"Expected: {dbp_expected}\nActual: {dbp_output}"
                    })
                    continue
                if not odb_output == odb_expected:
                    report["failed"].append({
                        "file": filename,
                        "message": f"Expected: {odb_expected}\nActual: {odb_output}"
                    })
                    continue
                report["succeeded"].append({
                    "file": filename
                })

            elif basename.startswith("cn-"):
                if any(result["success"]
                       for compiler_type, compiler_plats in compiler_types.items()
                       for compiler_plat, result in compiler_plats.items()):
                    failed_names = [f"{compiler_type}/{compiler_plat}"
                                    for compiler_type, compiler_plats in compiler_types.items()
                                    for compiler_plat, result in compiler_plats.items()
                                    if result["success"]]
                    report["failed"].append({
                        "file": filename,
                        "message": f"Code expected not to compile, but compiled for targets: {', '.join(failed_names)}"
                    })
                    continue

                report["succeeded"].append({
                    "file": filename
                })

            elif basename.startswith("odbc-"):
                if any(result["success"] for compiler_plat, result in compiler_types["dbp"].items()):
                    failed_names = [f"dbp/{compiler_plat}"
                                    for compiler_plat, result in compiler_types["dbp"].items()
                                    if result["success"]]
                    report["failed"].append({
                        "file": filename,
                        "message": f"Code expected to not compile on DBP, but compiled on targets: {', '.join(failed_names)}"
                    })
                    continue

                expected = open(filename.replace(".dba", ".out"), "rb").read().decode("utf-8")
                if not odb_output == expected:
                    report["failed"].append({
                        "file": filename,
                        "message": f"Expected: {expected}\nActual: {odb_output}"
                    })
                    continue

                report["succeeded"].append({
                    "file": filename
                })

            elif basename.startswith("dbpc-"):
                if any(result["success"] for compiler_plat, result in compiler_types["odb"].items()):
                    failed_names = [f"odb/{compiler_plat}"
                                    for compiler_plat, result in compiler_types["odb"].items()
                                    if result["success"]]
                    report["failed"].append({
                        "file": filename,
                        "message": f"Code expected to not compile on DBP, but compiled on targets: {', '.join(failed_names)}"
                    })
                    continue

                expected = open(filename.replace(".dba", ".out"), "rb").read().decode("utf-8")
                if not dbp_output == expected:
                    report["failed"].append({
                        "file": filename,
                        "message": f"Expected: {expected}\nActual: {dbp_output}"
                    })
                    continue

                report["succeeded"].append({
                    "file": filename
                })

            else:
                report["failed"].append({
                    "file": f,
                    "message": "BUG: Unknown/unsupported filename"
                })
    open(os.path.join(workdir, "report.json"), "wb").write(json.dumps(report).encode("utf-8"))
    return True


async def do_status():
    async with lock:
        report = json.loads(open(os.path.join(workdir, "report.json"), "rb").read().decode("utf-8"))

    failed_count = len(report["failed"])
    success_count = len(report["succeeded"])
    total_count = failed_count + success_count

    msgs = [f"{success_count}/{total_count} test cases succeeded"]
    for failed in report["failed"][:2]:
        msgs.append(f"{failed['file']}\n{failed['message']}")
    await post_status_to_bot("\n\n".join(msgs))


@app.route("/ci-sources-push", methods=["POST"])
async def github_event_ci_sources_pushed():
    payload = await quart.request.get_data()
    if not verify_signature(payload, quart.request.headers["X-Hub-Signature-256"].replace("sha256=", ""), config["github"]["secret"]):
        quart.abort(403)

    event_type = quart.request.headers["X-GitHub-Event"]
    if not event_type == "push":
        return ""

    # only care about pushes to master branch
    data = json.loads(payload.decode("utf-8"))
    if not data["ref"].rsplit("/", 1)[-1] == "master":
        return ""

    await post_status_to_bot("CI run started")
    asyncio.ensure_future(pull_and_run_all())
    return ""


@app.route("/odbc-push", methods=["POST"])
async def github_event_odb_pushed():
    payload = await quart.request.get_data()
    if not verify_signature(payload, quart.request.headers["X-Hub-Signature-256"].replace("sha256=", ""), config["github"]["secret"]):
        quart.abort(403)

    event_type = quart.request.headers["X-GitHub-Event"]
    if not event_type == "push":
        return ""

    # only care about pushes to master branch
    data = json.loads(payload.decode("utf-8"))
    if not data["ref"].rsplit("/", 1)[-1] == "master":
        return ""

    return ""


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
