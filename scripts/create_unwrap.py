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

import msal
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
    parser.add_argument("--tenant", "-t", type=str, help="Microsoft Onedrive tenant ID")
    parser.add_argument("--client", "-c", type=str, help="Microsoft Onedrive client ID")
    parser.add_argument(
        "--work-dir", "-w", type=str, help="Working directory to use as a temp storage"
    )

    return parser.parse_args()


class ProcessWithException(multiprocessing.Process):
    def __init__(self, *args, **kwargs) -> None:
        multiprocessing.Process.__init__(self, *args, **kwargs)
        self._parent_conn, self._child_conn = multiprocessing.Pipe()
        self._exception = None

    def run(self) -> None:
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


class Copernicus:
    def __init__(self, username: str, password: str) -> None:
        logging.info("Getting token from Copernicus ...")
        self.token = self.__get_access_token(username, password)
        logging.info("Token get!")

    def __get_access_token(username: str, password: str) -> str:
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

    def __get_file(self, data_id) -> None:
        url = f"https://zipper.dataspace.copernicus.eu/odata/v1/Products({data_id})/$value"
        headers = {"Authorization": f"Bearer {self.access_token}"}

        session = requests.Session()
        session.headers.update(headers)
        response = session.get(url, headers=headers, stream=True)

        with open(data_id, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)

    def download_products(self, filename1: str, filename2: str) -> None:
        logging.info("Starting to download files ...")
        args = [[filename1, self.token], [filename2, self.token]]
        pool = multiprocessing.Pool()
        pool.starmap(self.__get_file, args)
        pool.close()
        logging.info("Files downloaded!")


class Process:
    def __init__(self, filename1: str, filename2: str) -> None:
        logging.info("Preparing processing parameters ...")
        self.__update_xml(filename1, filename2)
        logging.info("XMLs updated!")

    def __update_xml(filename1: str, filename2: str) -> None:
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
                        temp_dir
                        + "/output/"
                        + "Orb_Stack_Ifg_Deb_DInSAR_mrg_ML_Flt.dim"
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
        # It should be separate file Ref: https://forum.step.esa.int/t/snaphu-export-does-not-generate-a-corrfile/27663/36
        tree = xml.etree.ElementTree.parse("TOPSAR_SnaphuExport.xml")
        root = tree.getroot()

        for elem in root.findall("node"):
            if elem.get("id") in ["Read", "SnaphuExport"]:
                params = elem.find("parameters")
                if elem.get("id") == "Read":
                    params.find("file").text = (
                        temp_dir
                        + "/output/"
                        + "Orb_Stack_Ifg_Deb_DInSAR_mrg_ML_Flt.dim"
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

    def process() -> None:
        logging.info("Starting to process ...")

        # Pre-process
        log_file = open("gpt.log", "w")
        result = subprocess.run(
            ["/usr/local/snap/bin/gpt", "presnaphuexport.xml"], stdout=log_file
        )
        log_file.flush()

        if result.returncode != 0:
            logging.error(f"GPT returned error code {result.returncode}")
            return
        logging.info("Pre-process completed! Exporting snaphu ...")

        # Export snaphu
        result = subprocess.run(
            ["/usr/local/snap/bin/gpt", "snaphuexport.xml"], stdout=log_file
        )
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


class MSOnedrive:
    def __init__(self, tenant: str, client: str) -> None:
        logging.info("Getting token from Onedrive ...")
        token = self.__get_access_token(tenant, client)
        logging.info("Token get!")

        self.drive_app = OneDrive(token)

    def __get_access_token(tenant: str, client: str) -> str:
        app = msal.PublicClientApplication(
            authority=("https://login.microsoftonline.com/" + tenant), client_id=client
        )

        flow = app.initiate_device_flow(scopes=["Files.Read.All"])
        result = app.acquire_token_by_device_flow(flow)

        if "access_token" in result:
            return result["access_token"]
        else:
            raise Exception(result["error"])

    def __upload_file(self, local_path: str, remote_path: str) -> None:
        self.drive_app.upload_item(item_path=remote_path, file_path=local_path)
        logging.info(f"Uploaded {local_path} to {remote_path}")

    def upload_results(self, local_path: str, onedrive_path: str, flag) -> None:
        logging.info("Uploading files ...")

        # Get list of files
        files = os.listdir(local_path)
        args = [
            (self.drive_app, os.path.join(local_path, file), onedrive_path)
            for file in files
        ]

        # Upload files
        pool = multiprocessing.Pool()
        pool.starmap(self.__upload_file, args)
        pool.close()

        logging.info("All files uploaded")

        with flag.get_lock():
            flag.value = True
        time.sleep(10)

        # Upload log files manually to get all logs
        self.__upload_file(self.drive_app, "process.log", onedrive_path)
        self.__upload_file(self.drive_app, "usage.log", onedrive_path)
        self.__upload_file(self.drive_app, "snaphu.log", onedrive_path)
        self.__upload_file(self.drive_app, "gpt.log", onedrive_path)


def main_process(args, flag):
    logging.info(f"Processing data {args.input_file1} and {args.input_file2}")

    copernicus = Copernicus(args.user, args.passwd)
    process = Process(args.input_file1, args.input_file2)
    drive = MSOnedrive(args.tenant, args.client)

    copernicus.download_products(args.input_file1, args.input_file2)
    process.process()
    drive.upload_results(temp_dir + "/output", "ESAProcess/", flag)


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
    if args.tenant is None:
        logging.error("Provide a tenant ID for Microsoft Onedrive with --tenant")
        sys.exit(-1)
    if args.client is None:
        logging.error("Provide a client ID for Microsoft Onedrive with --client")
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
