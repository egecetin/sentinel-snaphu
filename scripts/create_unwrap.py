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

import pysftp


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
    # parser.add_argument("--remote-ip", "-ri", type=str, help="Remote server IP address")
    # parser.add_argument("--remote-user", "-ru", type=str, help="Remote server username")
    # parser.add_argument("--droplet-id", "-di", type=str, help="DigitalOcean droplet ID")
    # parser.add_argument(
    #     "--droplet-token",
    #     "-dt",
    #     type=str,
    #     help="DigitalOcean Personal Access Token (PAT)",
    # )

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

    def __get_access_token(self, username: str, password: str) -> str:
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

    def _get_file(self, data_id: str, filename: str) -> None:
        url = f"https://zipper.dataspace.copernicus.eu/odata/v1/Products({data_id})/$value"
        headers = {"Authorization": f"Bearer {self.token}"}

        session = requests.Session()
        session.headers.update(headers)
        r = session.get(url, headers=headers, stream=True)

        with open(f"data/{filename}", "wb") as file:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)
        logging.info(f"{filename} downloaded")

        # For fix https://forum.step.esa.int/t/iw3-missing-when-downloading-product-from-data-space/40035
        logging.info(f"Extracting {filename}")
        self.__unzip_file(f"data/{filename}", f"data/")
        logging.info(f"Extracted {filename}")

    def __unzip_file(self, filename: str, path: str) -> None:
        shutil.unpack_archive(filename, path, "zip")

    def get_filename(self, data_id: str) -> str:
        url = (
            f"https://zipper.dataspace.copernicus.eu/odata/v1/Products({data_id})/Nodes"
        )
        headers = {"Authorization": f"Bearer {self.token}"}

        session = requests.Session()
        session.headers.update(headers)
        try:
            r = session.get(url, headers=headers, stream=True)
            r.raise_for_status()
        except Exception as e:
            raise Exception(f"Name query failed: {r.json()}")
        return r.json()["result"][0]["Name"]

    def download_products(
        self, data_id1: str, filename1: str, data_id2: str, filename2: str
    ) -> None:
        logging.info("Starting to download files ...")
        args = [[data_id1, filename1], [data_id2, filename2]]
        pool = multiprocessing.Pool()
        pool.starmap(self._get_file, args)
        pool.close()
        logging.info("Files downloaded!")


class Process:
    def __init__(self, filename1: str, filename2: str) -> None:
        logging.info("Preparing processing parameters ...")
        self.__update_xml(filename1, filename2)
        logging.info("XMLs updated!")

    def __update_xml(self, filename1: str, filename2: str) -> None:
        os.makedirs("data/", exist_ok=True)

        # Parse and update the pre-process XML file
        tree = xml.etree.ElementTree.parse("TOPSAR_PreSnaphuExportIWAllSwaths.xml")
        root = tree.getroot()

        for elem in root.findall("node"):
            if elem.get("id") in ["Read", "Read(2)", "Write"]:
                params = elem.find("parameters")
                if elem.get("id") == "Read":
                    params.find("file").text = (
                        "data/" + filename1[:-4] + "/manifest.safe"
                    )
                elif elem.get("id") == "Read(2)":
                    params.find("file").text = (
                        "data/" + filename2[:-4] + "/manifest.safe"
                    )
                elif elem.get("id") == "Write":
                    targetFolder = "output/"
                    os.makedirs(targetFolder, exist_ok=True)
                    params.find("file").text = (
                        "output/" + "Orb_Stack_Ifg_Deb_DInSAR_mrg_ML_Flt.dim"
                    )
                else:
                    raise Exception(
                        "This shouldn't happen! elem id none of the Read, Read(2), Write or SnaphuExport"
                    )

        tree.write("data/presnaphuexport.xml")

        # Parse the snaphu XML file
        # It should be separate file Ref: https://forum.step.esa.int/t/snaphu-export-does-not-generate-a-corrfile/27663/36
        tree = xml.etree.ElementTree.parse("TOPSAR_SnaphuExport.xml")
        root = tree.getroot()

        for elem in root.findall("node"):
            if elem.get("id") in ["Read", "SnaphuExport"]:
                params = elem.find("parameters")
                if elem.get("id") == "Read":
                    params.find("file").text = (
                        "output/" + "Orb_Stack_Ifg_Deb_DInSAR_mrg_ML_Flt.dim"
                    )
                elif elem.get("id") == "SnaphuExport":
                    targetFolder = "output/snaphu_export/"
                    os.makedirs(targetFolder, exist_ok=True)
                    params = elem.find("parameters")
                    params.find("targetFolder").text = targetFolder
                else:
                    raise Exception(
                        "This shouldn't happen! elem id neither Read nor SnaphuExport"
                    )

        tree.write("data/snaphuexport.xml")

    def process(self) -> None:
        logging.info("Starting to process ...")

        # Pre-process
        log_file = open("gpt.log", "w")
        result = subprocess.run(
            ["/usr/local/snap/bin/gpt", "data/presnaphuexport.xml"],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        log_file.flush()

        if result.returncode != 0:
            logging.error(f"GPT returned error code {result.returncode}")
            return
        logging.info("Pre-process completed! Exporting snaphu ...")

        # Export snaphu
        result = subprocess.run(
            ["/usr/local/snap/bin/gpt", "data/snaphuexport.xml"],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        log_file.close()

        if result.returncode != 0:
            logging.error(f"GPT returned error code {result.returncode}")
            return
        logging.info("Snaphu exported! Starting to unwrap ...")

        # Read snaphu command from config
        file_snaphu = open("output/snaphu_export/snaphu.conf", "r")
        lines = file_snaphu.readlines()

        log_file = open("snaphu.log", "w")
        result = subprocess.run(
            lines[6].replace("#", "").strip(), stdout=log_file, stderr=subprocess.STDOUT
        )
        log_file.close()

        if result.returncode != 0:
            logging.error(f"Unwrap returned error code {result.returncode}")
            return
        logging.info("Unwrap complete! Moving data ...")

        shutil.move(lines[26].split()[1], "output/" + lines[26].split()[1])
        logging.info("Data moved to output folder!")

        logging.info("Process complete!")


class SFTP:
    def __init__(self, host: str, username: str) -> None:
        logging.info("Creating SFTP connection ...")
        self.sftp = pysftp.Connection(host, username)
        logging.info("SFTP connection established!")

    def upload_results(self, local_path: str, remote_path: str, flag) -> None:
        logging.info("Uploading files ...")
        self.sftp.put_r(local_path, remote_path)
        logging.info("All files uploaded")

        with flag.get_lock():
            flag.value = True
        time.sleep(10)

        # Upload log files manually to get all logs
        self.sftp.put("process.log", remote_path)
        self.sftp.put("usage.log", remote_path)
        self.sftp.put("snaphu.log", remote_path)
        self.sftp.put("gpt.log", remote_path)

    def __del__(self) -> None:
        self.sftp.close()


def main_process(args, flag):
    logging.info(f"Processing data {args.input_file1} and {args.input_file2}")

    copernicus = Copernicus(args.user, args.passwd)
    filename1 = copernicus.get_filename(args.input_file1) + ".zip"
    filename2 = copernicus.get_filename(args.input_file2) + ".zip"
    process = Process(filename1, filename2)
    # storage = SFTP(args.remote_ip, args.remote_user)

    copernicus.download_products(
        args.input_file1, filename1, args.input_file2, filename2
    )
    process.process()
    # storage.upload_results("output", "/home/ESAProcess/", flag)


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
    # if args.remote_ip is None:
    #     logging.error("Provide a remote IP address of SFTP server with --remote-ip")
    #     sys.exit(-1)
    # if args.remote_user is None:
    #     logging.error("Provide a remote user of SFTP server with --remote-user")
    #     sys.exit(-1)
    # if args.droplet_id is None:
    #     logging.error("Provide a droplet ID with --droplet-id")
    #     sys.exit(-1)
    # if args.droplet_token is None:
    #     logging.error("Provide a droplet token with --droplet-token")
    #     sys.exit(-1)

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

    # Send destroy command to droplet
    # headers = {"Authorization": f"Bearer {args.token}"}
    # response = requests.delete(
    #     "https://api.digitalocean.com/v2/droplets/"
    #     + args.droplet_id
    #     + "?include_resources=true",
    #     headers=headers,
    #     timeout=30,
    # )

    # logging.info(f"Received response from DigitalOcean: {response.text}")
    logging.info("Goodbye!")
