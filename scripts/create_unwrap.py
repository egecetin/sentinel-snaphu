import argparse
import logging
import multiprocessing
import os
import psutil
import requests
import shutil
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree

from msdrive import OneDrive


def parse_args() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-file1", "-i1", type=str, help="Input file 1")
    parser.add_argument("--input-file2", "-i2", type=str, help="Input file 2")
    parser.add_argument(
        "--user", "-u", type=str, help="Copernicus Open Access Hub username"
    )
    parser.add_argument(
        "--passwd", "-p", type=str, help="Copernicus Open Access Hub password"
    )
    parser.add_argument(
        "--token", "-t", type=str, help="Microsoft Onedrive access token"
    )
    parser.add_argument(
        "--work-dir", "-w", type=str, help="Working directory to use as a temp storage"
    )

    return parser.parse_args()


class ProcessWithException(multiprocessing.Process):
    def __init__(self, *args, **kwargs):
        multiprocessing.Process.__init__(self, *args, **kwargs)
        self._parent_conn, self._child_conn = multiprocessing.Pipe()
        self._exception = None

    def run(self):
        try:
            multiprocessing.Process.run(self)
            self._child_conn.send(None)
        except Exception as e:
            tb = traceback.format_exc()
            self._child_conn.send((e, tb))

    @property
    def exception(self):
        if self._parent_conn.poll():
            self._exception = self._parent_conn.recv()
        return self._exception


def get_access_token(username: str, password: str) -> str:
    data = {
        "client_id": "cdse-public",
        "username": username,
        "password": password,
        "grant_type": "password",
    }
    try:
        r = requests.post(
            "https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token",
            data=data,
        )
        r.raise_for_status()
    except Exception as e:
        raise Exception(
            f"Access token creation failed. Response from the server was: {r.json()}"
        )
    return r.json()["access_token"]


def get_file(data_id, access_token):
    url = f"https://zipper.dataspace.copernicus.eu/odata/v1/Products({data_id})/$value"
    headers = {"Authorization": f"Bearer {access_token}"}

    session = requests.Session()
    session.headers.update(headers)
    response = session.get(url, headers=headers, stream=True)

    with open(data_id, "wb") as file:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                file.write(chunk)


def download_products(
    username: str, password: str, filename1: str, filename2: str
) -> None:
    logging.info("Getting token ...")
    token = get_access_token(username, password)
    logging.info("Token get!")

    # Download files
    logging.info("Starting to download files ...")
    args = [[filename1, token], [filename2, token]]
    pool = multiprocessing.Pool()
    pool.starmap(get_file, args)
    pool.close()

    logging.info("Files downloaded!")


def update_xml(filename1: str, filename2: str) -> None:
    logging.info("Preparing processing parameters ...")

    # Parse and update the pre-process XML file
    tree = xml.etree.ElementTree.parse("TOPSAR_PreSnaphuExportIWAllSwaths.xml")
    root = tree.getroot()

    for elem in root.findall("node"):
        if elem.get("id") in ["Read", "Read(2)", "Write", "SnaphuExport"]:
            params = elem.find("parameters")
            if elem.get("id") == "Read":
                params.find("file").text = temp_dir + "/" + filename1
            elif elem.get("id") == "Read(2)":
                params.find("file").text = temp_dir + "/" + filename2
            elif elem.get("id") == "Write":
                targetFolder = temp_dir + "/output/"
                os.makedirs(targetFolder, exist_ok=True)
                params.find("file").text = (
                    temp_dir + "/output/" + "Orb_Stack_Ifg_Deb_DInSAR_mrg_ML_Flt.dim"
                )
            elif elem.get("id") == "SnaphuExport":
                targetFolder = temp_dir + "/" + "snaphu_export/"
                os.makedirs(targetFolder, exist_ok=True)
                params = elem.find("parameters")
                params.find("targetFolder").text = targetFolder
            else:
                raise Exception(
                    "This shouldn't happen! elem id none of the Read, Read(2), Write or SnaphuExport"
                )

    tree.write("presnaphuexport.xml")

    # Parse the snaphu XML file
    tree = xml.etree.ElementTree.parse("TOPSAR_SnaphuExport.xml")
    root = tree.getroot()

    for elem in root.findall("node"):
        if elem.get("id") in ["Read", "SnaphuExport"]:
            params = elem.find("parameters")
            if elem.get("id") == "Read":
                params.find("file").text = (
                    temp_dir + "/output/" + "Orb_Stack_Ifg_Deb_DInSAR_mrg_ML_Flt.dim"
                )
            elif elem.get("id") == "SnaphuExport":
                targetFolder = temp_dir + "/" + "snaphu_export/"
                os.makedirs(targetFolder, exist_ok=True)
                params = elem.find("parameters")
                params.find("targetFolder").text = targetFolder
            else:
                raise Exception(
                    "This shouldn't happen! elem id neither Read nor SnaphuExport"
                )

    tree.write("snaphuexport.xml")

    logging.info("XMLs updated!")


def process() -> None:
    logging.info("Starting to process ...")

    # Pre-process
    log_file = open("gpt.log", "w")
    result = subprocess.run(["gpt", "presnaphuexport.xml"], stdout=log_file)
    log_file.flush()

    if result.returncode != 0:
        logging.error(f"GPT returned error code {result.returncode}")
        return
    logging.info("Pre-process completed! Exporting snaphu ...")

    # Export snaphu
    result = subprocess.run(["gpt", "snaphuexport.xml"], stdout=log_file)
    log_file.close()

    if result.returncode != 0:
        logging.error(f"GPT returned error code {result.returncode}")
        return
    logging.info("Snaphu exported! Starting to unwrap ...")

    # Read snaphu command from config
    file_snaphu = open(temp_dir + "/" + "snaphu_export/snaphu.conf", "r")
    lines = file_snaphu.readlines()

    log_file = open("snaphu.log", "w")
    result = subprocess.run(lines[6].replace("#", "").strip(), stdout=log_file)
    log_file.close()

    if result.returncode != 0:
        logging.error(f"Unwrap returned error code {result.returncode}")
        return
    logging.info("Unwrap complete! Moving data ...")

    shutil.move(lines[26].split()[1], "output/" + lines[26].split()[1])
    logging.info("Data moved to output folder!")

    logging.info("Process complete!")


def upload_file(drive: str, local_path: str, remote_path: str) -> None:
    drive.upload_item(item_path=remote_path, file_path=local_path)
    logging.info(f"Uploaded {local_path} to {remote_path}")


def upload_results(token: str, local_path: str, onedrive_path: str, flag) -> None:
    logging.info("Uploading files ...")

    drive = OneDrive(token)

    # Get list of files
    files = os.listdir(local_path)
    args = [(drive, os.path.join(local_path, file), onedrive_path) for file in files]

    # Upload files
    pool = multiprocessing.Pool()
    pool.starmap(upload_file, args)
    pool.close()

    logging.info("All files uploaded")

    with flag.get_lock():
        flag.value = True
    time.sleep(10)

    # Upload log files manually to get all logs
    upload_file(drive, "process.log", onedrive_path)
    upload_file(drive, "usage.log", onedrive_path)
    upload_file(drive, "snaphu.log", onedrive_path)
    upload_file(drive, "gpt.log", onedrive_path)


def main_process(args, flag):
    logging.info(f"Processing data {args.input_file1} and {args.input_file2}")

    update_xml(args.input_file1, args.input_file2)
    download_products(args.user, args.passwd, args.input_file1, args.input_file2)
    process()
    upload_results(args.token, temp_dir + "/output", "ESAProcess/", flag)


def main_sentry(args, flag):
    logging.info("Sentry started!")
    file = open("usage.log", "w")
    file.write("time,cpu,ram,disk,us,ds\n")

    # Get first network io
    io = psutil.net_io_counters()
    bytes_sent, bytes_recv = io.bytes_sent, io.bytes_recv
    while True:
        time.sleep(5)

        io_2 = psutil.net_io_counters()

        t = time.time()
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        us, ds = io_2.bytes_sent - bytes_sent, io_2.bytes_recv - bytes_recv
        file.write(f"{t},{cpu},{ram},{disk},{us},{ds}\n")
        file.flush()

        if flag.value:
            break

        bytes_sent, bytes_recv = io_2.bytes_sent, io_2.bytes_recv

    file.close()
    logging.info("Sentry stopped!")


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(
        filename="process.log",
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.input_file1 is None:
        logging.error("Provide a input file name with --input-file1")
        sys.exit(-1)
    if args.input_file2 is None:
        logging.error("Provide a input file name with --input-file2")
        sys.exit(-1)
    if args.user is None:
        logging.error("Provide a username for Copernicus Hub with --user")
        sys.exit(-1)
    if args.passwd is None:
        logging.error("Provide a password for Copernicus Hub with --passwd")
        sys.exit(-1)
    if args.token is None:
        logging.error("Provide a token for Microsoft Onedrive with --token")
        sys.exit(-1)
    if args.work_dir is None:
        logging.warn("Using current directory as working directory")
        temp_dir = os.getcwd()

    flag = multiprocessing.Value("b", False)

    processor = ProcessWithException(target=main_process, args=(args, flag))
    sentry = ProcessWithException(target=main_sentry, args=(args, flag))

    sentry.start()
    time.sleep(1)
    processor.start()

    while processor.is_alive() and sentry.is_alive():
        time.sleep(3)

    if not processor.is_alive() and not sentry.is_alive():
        sentry.join()
        processor.join()
    else:
        if not sentry.is_alive():
            error, traceback = sentry.exception
            logging.error(f"Exception caught for sentry: {error}")
            logging.error(f"{traceback}")
        if not processor.is_alive():
            error, traceback = processor.exception
            logging.error(f"Exception caught for processing: {error}")
            logging.error(f"{traceback}")
        sentry.kill()
        processor.kill()
