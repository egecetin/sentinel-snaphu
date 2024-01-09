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

import pysftp
import pyjavaproperties


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
        if os.path.isfile(f"data/{filename}"):
            logging.info(f"{filename} detected in directory skipping download")
        else:
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
        if os.path.isdir(f"data/{filename[:-4]}"):
            logging.info(f"{filename[:-4]} detected in directory skipping extracting")
        else:
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
    def __init__(self, filename1: str, filename2: str, subswath: str) -> None:
        self.filename1 = filename1
        self.filename2 = filename2
        self.subswath = subswath
        self.output_filename = (
            self.filename1[:4]
            + self.subswath
            + self.filename1[6:33]
            + self.filename2[17:33]
            + "Orb_Stack_Ifg_Deb_DInSAR_mrg_ML_Flt.dim"
        )

        logging.info("Preparing processing parameters ...")
        self.__prepare()
        logging.info("Processing parameters updated!")

    def __prepare(self) -> None:
        # Update properties file for process
        prop = pyjavaproperties.Properties()
        prop.load(open("process.properties"))

        prop["input_file_1"] = "data/" + self.filename1[:-4] + "/manifest.safe"
        prop["input_file_2"] = "data/" + self.filename2[:-4] + "/manifest.safe"
        prop["output_file"] = "output/" + self.output_filename
        prop["subswath"] = self.subswath

        prop.store(open("data/process.properties", "w"))

    def process(self) -> str:
        logging.info("Starting to process " + self.subswath + " ...")

        # Pre-process
        log_file = open("output/gpt.log", "a")
        result = subprocess.run(
            [
                "/usr/local/snap/bin/gpt",
                "TOPSAR_PreSnaphuExportIW.xml",
                "-p",
                "data/process.properties",
                "-J-Xmx"
                + str(int(psutil.virtual_memory().total / (1024**3) * 0.75))
                + "G",
                "-Dsnap.jai.tileCacheSize="
                + str(int(psutil.virtual_memory().total / (1024**3) * 0.75 * 0.5)),
            ],
            stdout=log_file,
            stderr=log_file,
        )
        log_file.flush()

        if result.returncode != 0:
            logging.error(f"GPT returned error code {result.returncode}")
            return ""
        logging.info("Pre-process completed! Exporting snaphu ...")

        # Export snaphu
        result = subprocess.run(
            [
                "/usr/local/snap/bin/gpt",
                "TOPSAR_SnaphuExport.xml",
                "-p",
                "data/process.properties",
                "-J-Xmx"
                + str(int(psutil.virtual_memory().total / (1024**3) * 0.75))
                + "G",
                "-Dsnap.jai.tileCacheSize="
                + str(int(psutil.virtual_memory().total / (1024**3) * 0.75 * 0.5)),
            ],
            stdout=log_file,
            stderr=log_file,
        )
        log_file.close()

        if result.returncode != 0:
            logging.error(f"GPT returned error code {result.returncode}")
            return ""
        logging.info("Snaphu exported! Starting to unwrap ...")

        # Read snaphu command from config
        file_snaphu = open(
            "output/snaphu_export/" + self.output_filename[:-4] + "/snaphu.conf", "r"
        )
        lines = file_snaphu.readlines()

        log_file = open("output/snaphu.log", "a")
        result = subprocess.run(
            lines[6].replace("#", "").strip().split(),
            cwd=("output/snaphu_export/" + self.output_filename[:-4]),
            stdout=log_file,
            stderr=log_file,
        )
        log_file.close()

        if result.returncode != 0:
            logging.error(f"Unwrap returned error code {result.returncode}")
            return ""

        logging.info("Process complete!")
        return self.output_filename[:-4]


class SFTP:
    def __init__(self, host: str, username: str, port: int) -> None:
        logging.info("Creating SFTP connection ...")
        self.sftp = pysftp.Connection(host, username, port)
        logging.info("SFTP connection established!")

    def upload_files(self, local_path: str, remote_path: str) -> None:
        logging.info(f"Uploading {local_path} ...")
        self.sftp.put_r(local_path, remote_path)
        logging.info(f"{local_path} uploaded!")

        logging.info(f"Removing {local_path} ...")
        if os.path.isfile(local_path):
            os.remove(local_path)
        elif os.path.isdir(local_path):
            shutil.rmtree(local_path)
        else:
            logging.warn(f"{local_path} not a file or directory")
        logging.info(f"{local_path} removed!")

    def __del__(self) -> None:
        self.sftp.close()


def main_process(args, flag):
    logging.info(f"Processing data {args.input_file1} and {args.input_file2}")

    copernicus = Copernicus(args.user, args.passwd)
    filename1 = copernicus.get_filename(args.input_file1) + ".zip"
    filename2 = copernicus.get_filename(args.input_file2) + ".zip"

    copernicus.download_products(
        args.input_file1, filename1, args.input_file2, filename2
    )
    for subswath in ["IW1", "IW2", "IW3"]:
        process = Process(filename1, filename2, subswath)
        output_name = process.process()

    # if (len(output_name)):
    #     queue.put(output_name + ".data")
    #     queue.put(output_name + ".dim")
    #     queue.put("output/snaphu_export/" + output_name)

    with flag.get_lock():
        flag.value = True
    time.sleep(10)


def main_sentry(args, flag):
    logging.info("Sentry started!")
    file = open("output/usage.log", "a")
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

    os.makedirs("data/", exist_ok=True)
    os.makedirs("output/snaphu_export", exist_ok=True)

    logging.basicConfig(
        filename="output/process.log",
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

    flag = multiprocessing.Value("b", False)

    processor = ProcessWithException(target=main_process, args=(args, flag))
    sentry = ProcessWithException(target=main_sentry, args=(args, flag))
    # uploader = ProcessWithException(target=main_upload, args=(args, flag))

    sentry.start()
    time.sleep(1)
    processor.start()
    # uploader.start()

    while processor.is_alive() and sentry.is_alive():  # and uploader.is_alive():
        time.sleep(3)

    if processor.is_alive() or sentry.is_alive():  # or uploader.is_alive():
        if not sentry.is_alive():
            error, traceback = sentry.exception
            logging.error(f"Exception caught for sentry: {error}")
            logging.error(f"{traceback}")
        if not processor.is_alive():
            error, traceback = processor.exception
            logging.error(f"Exception caught for processing: {error}")
            logging.error(f"{traceback}")
        # if not uploader.is_alive():
        #     error, traceback = uploader.exception
        #     logging.error(f"Exception caught for uploader: {error}")
        #     logging.error(f"{traceback}")
        sentry.kill()
        processor.kill()
        # uploader.kill()

    logging.info("Goodbye!")
