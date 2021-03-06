import argparse
import os
import hashlib
import base64
import sqlite3
import glob
import shutil
import datetime
import re
import zipfile
import sys

# TODO use pathlib vs os.path calls? this is 3.4 only
# http://docs.sqlalchemy.org/en/rel_0_9/orm/tutorial.html ??
# http://docs.python.org/3.4/howto/logging-cookbook.html

# a list of valid file extensions to import. anything else will be skipped. make it a set in case people add dupes
extensions = {'.jpg', '.avi', '.ram', '.rm', '.wmv', '.pdf', '.mov', '.mp4', '.flv', '.jpe', '.jpeg', '.mpg', '.mpe',
              '.mpeg', '.png', '.3g2', '.3gp', '.asf', '.bmp', '.divx', '.gif', '.jpg', '.m1v', '.vob', '.mod', '.tif',
              '.mkv', '.jp2', '.psd', '.m4v', '.pcx'}

# a list of extensions to delete. If any of these extensions are found in 'extensions' the import will be cancelled
auto_delete_extensions = {'.db', '.com', '.scr', '.htm', '.html', '.url', '.thm', '.tmp', '.ds_store', '.ico', '.rtf',
                          '.doc', '.ini', '.ascii', '.dat', '.svg'}

BUFFER_SIZE = 65536  # 8192 # file reading buffer size 8192 * 64?

# logger = logging.getLogger('filemgr')
# logger.setLevel(logging.CRITICAL)
# fh = logging.FileHandler('filemgr_debug.log')
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# fh.setFormatter(formatter)
# logger.addHandler(fh)


def safeprint(s):
    try:
        print(s)
    except UnicodeEncodeError:
        print(s.encode('utf8').decode(sys.stdout.encoding))


class ED2KHash(object):
    MAGICLEN = 9728000

    def __init__(self):
        self.hashes = []
        self.pos = 0
        self.md4 = hashlib.new('md4')

    def update(self, data):
        data_len = len(data)
        for d in (data[i:i + ED2KHash.MAGICLEN] for i in range(0, data_len, ED2KHash.MAGICLEN)):
            self._update(d)

    def _update(self, data):
        data_len = len(data)
        assert data_len <= ED2KHash.MAGICLEN

        newpos = self.pos + data_len

        if newpos < ED2KHash.MAGICLEN:
            self.md4.update(data)
            self.pos = newpos
            return
        else:
            prev = data[:ED2KHash.MAGICLEN - self.pos]
            next_val = data[ED2KHash.MAGICLEN - self.pos:]
            self.md4.update(prev)
            self.hashes.append(self.md4.digest())
            self.md4 = hashlib.new('md4')
            self.md4.update(next_val)
            self.pos = len(next_val)
            return

    def digest(self):
        if len(self.hashes) == 0:
            return self.md4.digest()
        else:
            m = hashlib.new('md4')
            newhashes = self.hashes + [self.md4.digest()]
            m.update(b''.join(newhashes))
            return m.digest()


class ApplicationConfiguration(object):
    """
    Holds configuration values used in various places
    """

    def __init__(self):
        self.__database_name = 'filemgr.db3'
        self.__base_directory = ''
        self.__database_file = ''
        self.__delete_existing = ''
        self.__copy_new_destination = ''
        self.__export_directory = ''
        self.__rename_exported = False
        self.__zip_exported = False
        self.__delete_empty_directories = ''

    def get_database_name(self):
        return self.__database_name

    def set_database_name(self, database_name):
        self.__database_name = database_name

    database_name = property(get_database_name, set_database_name)

    def get_base_directory(self):
        return self.__base_directory

    def set_base_directory(self, base_directory):
        self.__base_directory = base_directory

    base_directory = property(get_base_directory, set_base_directory)

    def get_database_file(self):
        return self.__database_file

    def set_database_file(self, database_file):
        self.__database_file = database_file

    database_file = property(get_database_file, set_database_file)

    def get_delete_existing(self):
        return self.__delete_existing

    def set_delete_existing(self, delete_existing):
        self.__delete_existing = delete_existing

    delete_existing = property(get_delete_existing, set_delete_existing)

    def get_delete_empty_directories(self):
        return self.__delete_empty_directories

    def set_delete_empty_directories(self, delete_empty_directories):
        self.__delete_empty_directories = delete_empty_directories

    delete_empty_directories = property(get_delete_empty_directories, set_delete_empty_directories)

    def get_export_directory(self):
        return self.__export_directory

    def set_export_directory(self, export_directory):
        self.__export_directory = export_directory

    export_directory = property(get_export_directory, set_export_directory)

    def get_rename_exported(self):
        return self.__rename_exported

    def set_rename_exported(self, rename_exported):
        self.__rename_exported = rename_exported

    rename_exported = property(get_rename_exported, set_rename_exported)

    def get_zip_exported(self):
        return self.__zip_exported

    def set_zip_exported(self, zip_exported):
        self.__zip_exported = zip_exported

    zip_exported = property(get_zip_exported, set_zip_exported)

    def get_copy_new_destination(self):
        return self.__copy_new_destination

    def set_copy_new_destination(self, copy_new_destination):
        self.__copy_new_destination = copy_new_destination

    copy_new_destination = property(get_copy_new_destination, set_copy_new_destination)


def add_insert_hashtype(appconfig, hashtype):
    conn = sqlite3.connect(appconfig.database_file)

    c = conn.cursor()

    c.execute(
        "SELECT hashID FROM hashtypes WHERE hashtypes.hashname = ?;", (hashtype,))

    row = c.fetchone()

    if row is None:
        # insert last_insert_rowid()
        c.execute("INSERT INTO hashtypes (hashname) VALUES (?);", (hashtype,))

        conn.commit()

        rowid = c.lastrowid
    else:
        rowid = row[0]

    conn.close()

    return rowid


def add_file_to_db(appconfig, fileinfo):
    conn = sqlite3.connect(appconfig.database_file)

    c = conn.cursor()

    # check if hashtypes has an entry for each hash in hashes
    hashtypes = {}

    for key in fileinfo['hashes'].keys():
        hashtypes[key] = add_insert_hashtype(appconfig, key)

    filename = fileinfo['inputfile']
    basefilename = os.path.split(filename)[-1]
    basefilenameparts = os.path.splitext(basefilename)
    file_ext = basefilenameparts[1].lower()

    file_directory = os.path.join('files', fileinfo['hashes']['sha1b32'][0:2], fileinfo['hashes']['sha1b32'] + file_ext)

    # add file to files table
    c.execute("INSERT INTO files (importedfilename,filepath,filesize,comment) VALUES (?,?,?,?);",
              (fileinfo['inputfile'], file_directory, fileinfo['filesize'], ''))

    fileid = c.lastrowid

    # add each hash to file hashes
    for hashtype in hashtypes:
        c.execute("INSERT INTO filehashes (hashID,fileID,filehash) VALUES (?,?,?);",
                  (hashtypes[hashtype], fileid, fileinfo['hashes'][hashtype]))

    conn.commit()

    conn.close()


def import_files_work(appconfig, dirname):
    files_with_invalid_extensions = []  # list of files we didn't import.

    total_files = 0
    files_added_to_database = 0
    files_deleted = 0
    files_with_duplicate_hashes = []
    files_copied = 0

    # Looking up each hash is sllllllow, so pull em all in as a set and just look there!
    print("Getting existing hashes from database...", end='')
    existing_hashes = get_sha1b32_from_database(appconfig)

    print("Got {:,d} hashes from database. Looking for files.\n".format(len(existing_hashes)))

    for dirpath, dirnames, files in os.walk(dirname, topdown=False):

        total_files += len(files)

        file_counter = 0

        if len(files) > 0:
            safeprint("\n\tFound {:,d} files in {}. Processing...".format(len(files), dirpath))

            #   logger.info("Found {:,d} files in {}".format(len(files), dirpath))

        for name in files:
            full_path_name = os.path.join(dirpath, name)

            file_counter += 1

            if os.path.isfile(full_path_name):

                if os.path.getsize(full_path_name) == 0:
                    safeprint("\t\tDeleting 0 byte file '{}'.".format(full_path_name))
                    os.remove(full_path_name)
                    continue

                parts = os.path.splitext(name.lower())
                if len(parts) == 2:
                    ext = parts[1]

                    # some files are always bad, so just make em go away.
                    if ext in auto_delete_extensions:
                        safeprint(
                            '\t\t({} [{:,d}/{:,d}]): File {} has an autonuke extension. Deleting...'.format(
                                datetime.datetime.now().strftime('%x %X'),
                                file_counter,
                                len(files), full_path_name))
                        os.remove(full_path_name)
                        continue

                    if ext in extensions:
                        # logger.info(
                        #     "{} before fileinfo = get_file_data(full_path_name)".format(
                        #         datetime.datetime.now().strftime('%x %X')))

                        fileinfo = get_file_data(full_path_name)

                        # logger.info("{} after fileinfo = get_file_data(full_path_name)".format(
                        #     datetime.datetime.now().strftime('%x %X')))

                        if not fileinfo['hashes']['sha1b32'] in existing_hashes:
                            files_added_to_database += 1

                            safeprint("\t\t({} [{:,d}/{:,d}]): '{}' does not exist in database! Adding...".format
                                      (datetime.datetime.now().strftime('%x %X'),
                                       file_counter,
                                       len(files),
                                       full_path_name))

                            # since this is a new file, we add it to our set for future import operations
                            existing_hashes.add(fileinfo['hashes']['sha1b32'])

                            add_file_to_db(appconfig, fileinfo)
                        else:
                            pass  # do anything else here? should i check if file exists in file system? who cares tho
                            # as this syncs it up maybe here is where you do extra hashing of what is on file
                            #  system to make sure the 2 match, properly named, etc

                        # logger.info("{} before copied = copy_file_to_store(appconfig, fileinfo)):".format(
                        #     datetime.datetime.now().strftime('%x %X')))

                        copied = copy_file_to_store(appconfig, fileinfo)

                        if copied:
                            safeprint(
                                '\t\t({} [{:,d}/{:,d}]): File with SHA-1 Base32 hash {} does not exist in file store! Copying {:,d} bytes...'.format(
                                    datetime.datetime.now().strftime('%x %X'),
                                    file_counter,
                                    len(files), fileinfo['hashes']['sha1b32'], fileinfo['filesize']))

                        # logger.info("{} after copied = copy_file_to_store(appconfig, fileinfo)):".format(
                        #     datetime.datetime.now().strftime('%x %X')))

                        if not copied:
                            files_with_duplicate_hashes.append(full_path_name)
                        else:
                            files_copied += 1

                        if len(appconfig.copy_new_destination) > 0 and copied:
                            if not os.path.exists(appconfig.copy_new_destination):
                                os.mkdir(appconfig.copy_new_destination)

                            # TODO should this create the 2 char structure too? for now, just copy it

                            copy_name = os.path.join(appconfig.copy_new_destination, name)

                            unique_prefix = 0

                            while os.path.isfile(copy_name):
                                # file exists, so get a unique name
                                copy_name = os.path.join(appconfig.copy_new_destination,
                                                         str(unique_prefix) + "_" + name)
                                unique_prefix += 1

                            shutil.copyfile(full_path_name, copy_name)

                            outfile = os.path.join(appconfig.copy_new_destination,
                                                   "!!" + datetime.datetime.now().strftime(
                                                       "%Y-%m-%d") + " File copy log " + '.txt')
                            with open(outfile, 'a', encoding="utf-16") as logfile:
                                logfile.write(
                                    "{}: Copied {} to {}.\n".format(datetime.datetime.now(), full_path_name, copy_name))

                        if appconfig.delete_existing:
                            safeprint("\t\t({} [{:,d}/{:,d}]): Deleting '{}'...".format(
                                datetime.datetime.now().strftime('%x %X'),
                                file_counter,
                                len(files),
                                full_path_name))

                            if appconfig.delete_existing == 'yes':
                                os.remove(full_path_name)

                            files_deleted += 1
                    else:
                        files_with_invalid_extensions.append(os.path.join(dirpath, name))

        if appconfig.delete_empty_directories:
            if not os.listdir(dirpath):
                safeprint("\t\t({} [{:,d}/{:,d}]): Deleting empty directory '{}'...".format(
                    datetime.datetime.now().strftime('%x %X'), file_counter, len(files), dirpath))
                if appconfig.delete_empty_directories == 'yes':
                    os.rmdir(dirpath)

    return (files_added_to_database, total_files, files_deleted, files_copied, files_with_duplicate_hashes,
            files_with_invalid_extensions)


def file_exists_in_database(appconfig, fileinfo):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    c.execute(
        "SELECT filehashID FROM files, filehashes, hashtypes WHERE hashtypes.hashid = filehashes.hashid "
        "AND files.fileID = filehashes.fileID AND hashtypes.hashname = 'sha1b32' AND filehashes.filehash = ?;",
        (fileinfo['hashes']['sha1b32'],))

    row = c.fetchone()

    conn.close()

    if row is None:
        return False
    else:
        return True


def get_sha1b32_from_database(appconfig):
    # pull them out and cache on startup or when first pulled?

    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()

    hash_id = get_hash_id_from_hash_name(appconfig, "sha1b32")

    c.execute("SELECT filehash FROM filehashes WHERE hashid = ?;", (hash_id,))

    rows = c.fetchall()

    conn.close()

    hashes = [row[0] for row in rows]

    return set(hashes)


def copy_file_to_store(appconfig, fileinfo):
    """Checks datastore for a file with identical sha1b32 hash.
    if one exists, optionally delete the source file
    optionally copy new file to separate directory for sharing purposes
    """

    filename = fileinfo['inputfile']
    base_filename = os.path.split(filename)[-1]
    base_filename_parts = os.path.splitext(base_filename)
    file_ext = base_filename_parts[1].lower()

    files_directory = os.path.join(appconfig.base_directory, 'files')

    file_directory = os.path.join(files_directory, fileinfo['hashes']['sha1b32'][0:2])

    if not os.path.exists(file_directory):
        os.mkdir(file_directory)

    target_filemask = os.path.join(file_directory, fileinfo['hashes']['sha1b32'] + '*')

    dest_filename = os.path.join(file_directory, fileinfo['hashes']['sha1b32'] + file_ext)

    listing = glob.glob(target_filemask)

    file_copied = False

    if len(listing) == 0:
        shutil.copyfile(filename, dest_filename)
        file_copied = True

    return file_copied


def get_file_data(file):
    """
    Generates hashes for file and other file info such as size, etc.
    """
    # TODO can i use some kind of magic to determine mime type and forego extension?

    fileinfo = {'inputfile': file, 'filesize': os.path.getsize(file), 'hashes': {}}

    ed2k = ED2KHash()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    md4 = hashlib.new('md4')

    f = open(file, 'rb')
    buf = f.read(BUFFER_SIZE)
    while buf != b'':
        md5.update(buf)
        sha1.update(buf)
        md4.update(buf)
        ed2k.update(buf)
        buf = f.read(BUFFER_SIZE)
    f.close()

    sha1b16 = sha1.hexdigest().upper()
    sha1b32 = base64.b32encode(
        base64.b16decode(sha1b16.upper())).decode().upper()
    edonkey = base64.b16encode(ed2k.digest())
    md4hash = md4.hexdigest().upper()
    md5hash = md5.hexdigest().upper()

    fileinfo['hashes']['md4'] = md4hash

    fileinfo['hashes']['ed2k'] = edonkey.decode('utf-8').upper()
    fileinfo['hashes']['sha1b16'] = sha1b16
    fileinfo['hashes']['sha1b32'] = sha1b32
    fileinfo['hashes']['md5'] = md5hash

    parts = os.path.splitext(file.lower())
    ext = ''

    if len(parts) == 2:
        ext = parts[1]

    fileinfo['extension'] = ext.lower()
    fileinfo['file_store_name'] = sha1b32 + fileinfo['extension']

    return fileinfo


# def generate_missing_hashes(appconfig, file):
#     """ Given file, look for missing hashes, generate them, and update the
#     database """
#
#     return "not done yet"


def setup_base_directory(directory):
    try:
        if not os.path.exists(directory):
            print('{} does not exist! Creating...'.format(directory))
            os.mkdir(directory)

        subdir = os.path.join(directory, 'files')

        if not os.path.exists(subdir):
            os.mkdir(subdir)
    except:
        raise


def init_db(appconfig):
    # create, setup tables
    #one table is hashname
    #another is for files that references hashname pk
    #this allows for easy expanding if hashname is missing without schema changes
    conn = sqlite3.connect(appconfig.database_file)

    c = conn.cursor()

    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hashtypes';")

    row = c.fetchone()

    if row is None:
        print("!!!Database is missing. Creating...")
        c.execute('''CREATE TABLE hashtypes
             (hashID INTEGER PRIMARY KEY AUTOINCREMENT, hashname TEXT)''')

        c.execute('''CREATE TABLE files
             (fileID INTEGER PRIMARY KEY AUTOINCREMENT, importedfilename TEXT,
             filepath TEXT, filesize INTEGER, comment TEXT)''')

        c.execute('''CREATE TABLE filehashes
             (filehashID INTEGER PRIMARY KEY AUTOINCREMENT, hashID INTEGER, fileID INTEGER, filehash TEXT)''')

        conn.commit()

    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='importedpaths';")

    row = c.fetchone()

    if row is None:
        print("!!!Table 'importedpaths' is missing!. Creating...")
        c.execute('''CREATE TABLE importedpaths (pathID INTEGER PRIMARY KEY AUTOINCREMENT, importedpath TEXT,
                  imported_date TEXT, files_added_to_database INTEGER, total_files INTEGER, files_deleted INTEGER,
                  files_copied INTEGER, files_with_duplicate_hashes INTEGER, files_with_invalid_extensions INTEGER);''')

        conn.commit()

    #add indexes

    c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index';")

    row = c.fetchone()

    if row[0] == 0:
        print("!!!Indexes are missing. Creating...")
        c.execute('CREATE INDEX "IX_filehashes" ON "filehashes" ("filehash")')
        print("!File hash index created")
        c.execute('CREATE INDEX "IX_fileID" ON "filehashes" ("fileID")')
        print("!FileID index created")
        c.execute('CREATE UNIQUE INDEX "IU_filepath" ON "files" ("filepath", "filesize")')
        print("!File path/file size index created")
        c.execute('CREATE UNIQUE INDEX "IU_hashID_fileID" ON "filehashes" ("hashID", "filehash")')
        print("!HashID/file hash index created\n")
        c.execute('CREATE INDEX "IX_hashID" ON "filehashes" ("hashID")')
        print("!File hash index created")

        conn.commit()

    conn.close()


def add_import_path_to_db(appconfig, path_name, files_added_to_database, total_files, files_deleted, files_copied,
                          files_with_duplicate_hashes, files_with_invalid_extensions):
    conn = sqlite3.connect(appconfig.database_file)

    c = conn.cursor()

    c.execute(
        "INSERT INTO importedpaths (importedpath, imported_date, files_added_to_database, total_files, files_deleted, files_copied, files_with_duplicate_hashes, files_with_invalid_extensions) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        (path_name, datetime.datetime.now(), files_added_to_database, total_files, files_deleted, files_copied,
         len(files_with_duplicate_hashes), len(files_with_invalid_extensions)))

    conn.commit()

    conn.close()


def check_import_path_in_db(appconfig, path_name):
    conn = sqlite3.connect(appconfig.database_file)

    c = conn.cursor()

    c.execute("SELECT imported_date FROM importedpaths WHERE importedpath = ? ORDER BY imported_date DESC;",
              (path_name,))

    rows = c.fetchall()

    conn.close()
    #2014-02-05 10:22:30.214031
    dates = [datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f').strftime('%x %X') for row in rows]

    return dates


def generate_hash_list(appconfig, hash_type, suppress_file_info):
    outfile = os.path.join(appconfig.base_directory,
                           "Exported hash list_" + datetime.datetime.now().strftime("%H%M%S%f") + '.tsv')

    file_count = 0

    conn = sqlite3.connect(appconfig.database_file)

    file_cursor = conn.execute("SELECT files.filepath, files.filesize, files.fileID FROM files ORDER BY fileID")

    if hash_type == 'all':
        sql = 'SELECT hashid, hashname FROM hashtypes ORDER BY hashname ASC'
    else:
        sql = 'SELECT hashid, hashname FROM hashtypes WHERE hashname = "{}" ORDER BY hashname ASC'.format(hash_type)

    hash_types_cursor = conn.execute(sql)

    with open(outfile, 'w+', encoding="utf-16") as logfile:
        header = ['relative_path', 'file_size']

        if suppress_file_info:
            header.clear()

        hash_types = {}

        for hash_type_row in hash_types_cursor:
            header.append(hash_type_row[1])
            hash_types[hash_type_row[0]] = hash_type_row[1]

        logfile.write('\t'.join(header) + "\n")

        for file_row in file_cursor:
            file_count += 1
            file_id = file_row[2]

            # hash_types contains the id and hash name for all known hashes. for each of those, get that hash for
            # active file. if not present, tell the user

            row_values = [file_row[0], str(file_row[1])]  # this is what will build out each row

            if suppress_file_info:
                row_values.clear()

            for hash_id in sorted(hash_types,
                                  key=hash_types.get):  # sort it according to the hash names so the order is correct
                hash_cursor = conn.execute(
                    "SELECT filehashes.filehash, hashtypes.hashname FROM hashtypes INNER JOIN filehashes ON "
                    "filehashes.hashID = hashtypes.hashID WHERE filehashes.fileID = ? AND filehashes.hashID = ? "
                    "ORDER BY hashtypes.hashname ASC;",
                    (file_id, hash_id))
                row = hash_cursor.fetchone()
                if not row is None:
                    row_values.append(row[0])
                else:
                    row_values.append("Hash '{}' missing in database!".format(hash_types[hash_id]))
                hash_cursor.close()

            logfile.write('\t'.join(row_values) + "\n")

    conn.close()

    return file_count, outfile


def import_files(appconfig, directories):
    """
    Attempts to recursively import files from values in directories and writes log files with actions taken
    @param appconfig: Configuration data
    @param directories: a list of directories to import from
    """
    print("Importing from '{}'".format(",".join(directories)))
    for directory in directories:
        directory = directory.strip()
        if os.path.isdir(directory):

            import_history = check_import_path_in_db(appconfig, directory)

            if len(import_history) > 0:
                answer = input(
                    "\n\n**** '{}' has already been imported on:\n\n{}\n\nContinue: [y|N]: ".format(directory,
                                                                                                    '\n'.join(
                                                                                                        import_history)))
                if not answer.lower() == 'y':
                    print("**** Skipping '{}'\n".format(directory))
                    continue

            (files_added_to_database, total_files, files_deleted, files_copied, files_with_duplicate_hashes,
             files_with_invalid_extensions) = import_files_work(appconfig, directory)

            add_import_path_to_db(appconfig, directory, files_added_to_database, total_files, files_deleted,
                                  files_copied, files_with_duplicate_hashes, files_with_invalid_extensions)

            print(
                '\n' + '*' * 4 + """ {:,d} total files found. {:,d} copied to file store and {:,d} files were added to the database. {:,d} files had duplicate hashes. {:,d} files had invalid extensions (see log file for details)""".format(
                    total_files, files_copied, files_added_to_database, len(files_with_duplicate_hashes),
                    len(files_with_invalid_extensions)))

            directory_clean = re.sub('[^\w\-_\. ]', '_', directory)

            logfile_name = os.path.join(appconfig.base_directory,
                                        "Import log for " + directory_clean + " " + datetime.datetime.now().strftime(
                                            "%H%M%S%f") + '.txt')

            with open(logfile_name, 'w+', encoding="utf-16") as logfile:
                logfile.write('Directory processed: {}\n\n'.format(directory))
                logfile.write('Files found: {:,d}\n'.format(total_files))
                logfile.write('Files copied to file store: {:,d}\n'.format(files_copied))
                logfile.write('Files added to database: {:,d}\n'.format(files_added_to_database))

                logfile.write('Files with duplicate hashes: {:,d}\n\n'.format(len(files_with_duplicate_hashes)))

                if files_deleted > 0:
                    logfile.write('Number of deleted files: {:,d}\n\n'.format(files_deleted))

                logfile.write('*' * 78 + '\n\n')

                logfile.write('The following files had duplicate hashes and were not imported:\n\n')
                for item in files_with_duplicate_hashes:
                    logfile.write("{}\n".format(item))

                logfile.write('\n\nThe following files had invalid extensions and were not imported:\n\n')
                for item in files_with_invalid_extensions:
                    logfile.write("{}\n".format(item))

            if appconfig.delete_existing and files_deleted > 0:
                print(' ' * 5 + '{:,d} files were deleted'.format(files_deleted))
        else:
            print("\t'{}' does not exist!".format(directory))

    # after import, tell the user to see generated logs (one per directory) in the main directory
    # but only if we actually attempted to import something
    if len(directories) > 0 and 'logfile_name' in locals():
        print("\n\nSee log files in {} for details.".format(appconfig.base_directory))


def get_hash_id_from_hash_name(appconfig, hash_name):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    c.execute(
        "SELECT hashID FROM hashtypes WHERE hashname = ?;", (hash_name,))

    row = c.fetchone()

    conn.close()

    if row is None:
        return -1
    else:
        return int(row[0])


def check_file_exists_in_database(appconfig, hash_id, hash_value):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    c.execute(
        "SELECT files.filepath, files.filesize FROM filehashes INNER JOIN files ON files.fileID = filehashes.fileID "
        "WHERE filehashes.hashID = ? AND filehashes.filehash = ?;",
        (hash_id, hash_value))

    row = c.fetchone()

    conn.close()

    if row is None:
        db_info = ('', 0)
    else:
        db_info = (row[0], row[1])

    return db_info


def get_database_delta(appconfig, hash_set, hash_id):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    sql = "SELECT files.fileID, files.filepath FROM filehashes INNER JOIN files ON files.fileID = filehashes.fileID WHERE filehashes.hashID = ? AND filehashes.filehash NOT in ({0})".format(
        ', '.join('?' for _ in hash_set))
    params = hash_set
    params.insert(0, str(hash_id))

    c.execute(sql, params)

    rows = c.fetchall()

    conn.close()

    return rows


def get_hash_from_hash_id_and_file_id(appconfig, hash_id, file_id):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    c.execute(
        "SELECT filehashes.filehash FROM filehashes WHERE filehashes.hashID = ? AND filehashes.fileID = ?;",
        (hash_id, file_id))

    row = c.fetchone()

    conn.close()

    if row is None:
        return False
    else:
        return row[0]


def build_new_out_path(export_directory, new_hash, file_name):
    front = "files\\" + new_hash[0:2]
    mid = new_hash
    ext = os.path.splitext(file_name[1])[-1]
    out_path = os.path.join(export_directory, front, mid + ext.lower())
    return out_path


def copy_file(abs_path, log_file, out_path):
    if not os.path.exists(os.path.dirname(out_path)):
        os.makedirs(os.path.dirname(out_path))
    log_file.write("Copying '{}' to '{}'\n".format(abs_path, out_path))
    shutil.copyfile(abs_path, out_path)


def get_existing_hash_list(appconfig, hash_id):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    c.execute(
        "SELECT fileID, filehash FROM filehashes WHERE filehashes.hashID = ?;", (hash_id, ))

    existing_hashes = {}

  #   row_count = 0

    record = c.fetchone()

    while record:
        # if row_count % 1000000 == 0:
        #     print("{}: Database rows fetched: {:,d}".format(datetime.datetime.now().strftime('%x %X'), row_count))

        existing_hashes[record[1]] = record[0]
        record = c.fetchone()
      #  row_count += 1

    conn.close()

    return existing_hashes


def get_file_from_db(appconfig, file_id):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    c.execute(
        "SELECT filepath FROM files WHERE fileID = ?;", (file_id, ))

    record = c.fetchone()

    conn.close()

    return record[0]


def export_files(appconfig, export_existing, file_name):
    """
    Copies files from file store to a directory
    @param appconfig: basic config data
    @param export_existing: if true, export files in input file that are also in file store, else, export the opposite
    @param file_name: the file to read hash type and hashes from
    """
    hash_file = open(file_name)
    hash_name = hash_file.readline().strip().lower()
    hash_id = get_hash_id_from_hash_name(appconfig, hash_name)

    if hash_id == -1:
        print("Unknown hash type: '{}'. Export cancelled!".format(hash_name))
        return

    datetime_string = datetime.datetime.now().strftime("%H%M%S%f")
    export_directory = os.path.join(appconfig.export_directory,
                                    "Export run " + datetime_string + " for {}".format(hash_name))

    if not os.path.exists(export_directory):
        os.makedirs(export_directory)

    log_name = os.path.join(export_directory,
                            "Export log " + datetime_string + '.txt')

    log_file = open(log_name, 'w', encoding="utf-16")

    log_file.write("Looking for hashes in '{}'\n\n".format(file_name))
    log_file.write("Hash type: {}\n".format(hash_name))
    print("\t\tHash type: {}\n".format(hash_name))
    log_file.write("Zip exported: {}\n".format(appconfig.zip_exported))
    log_file.write("Rename exported: {}\n\n".format(appconfig.rename_exported))

    if export_existing:
        export_type = "Existing"
    else:
        export_type = "Delta"

    log_file.write("Export operation: {}\n\n".format(export_type))

    log_file.write("Copy log\n\n")

    found_files = 0
    hash_count = 0

    # TODO collect operations in a single list then iterate/copy after so as to remove duplicate code in loops for each
    if export_existing:
        for line in hash_file:
            line = line.strip()
            hash_count += 1

            (file_path, file_size) = check_file_exists_in_database(appconfig, hash_id, line)

            # TODO This needs cleaned up in regard to the paths. the database should store things in one format
            # right now its all bunged up

            if file_path:
                print(
                    "\t\t({:,d}) File with hash '{}' found! Copying {:,d} bytes...".format(hash_count, line, file_size))
                found_files += 1
                abs_path = os.path.join(appconfig.base_directory, file_path)

                if not os.path.isfile(abs_path):
                    front, ext = os.path.splitext(abs_path)

                    abs_path = front + ext.lower()

                abs_path = abs_path.replace("\\", "/")

                if appconfig.rename_exported and not hash_name == 'sha1b32':  # the default is sha1b32

                    out_path = build_new_out_path(export_directory, line, file_path.replace("\\", "/"))
                else:
                    out_path = os.path.join(export_directory, file_path.replace("\\", "/"))

                print("Copying '{}' to '{}'\n".format(abs_path, out_path))
                copy_file(abs_path, log_file, out_path)  # TODO Error handling here
    else:
        print("Getting hashes from file...")
        hashes = [line.strip() for line in hash_file]

        hash_set = set(hashes)  # get rid of any dupes
        hash_count = len(hash_set)

        file_count = 0

        print("Found {:,d} hashes in file!".format(hash_count))

        # sql wont work
        # export entire DB for hash_id to file containing: file_id and hash for hash_id
        # once done, read that into dictionary with hash: fileid
        # loop thru hash_set and remove similar items from dictionary
        # when done, export files remaining in dictionary

        print("Getting existing hashes from database...")
        existing_hash_list = get_existing_hash_list(appconfig, hash_id)

        print("Found {:,d} hashes in database!".format(len(existing_hash_list)))

        for hash in hash_set:
            if hash in existing_hash_list:
                del existing_hash_list[hash]

        print("After pruning there are {:,d} hashes to export.".format(len(existing_hash_list)))

        for value in existing_hash_list.values():
            # value is fileID for the file, so now we can get info on the file and export
            db_name = get_file_from_db(appconfig, value)
            if db_name:
                abs_path = os.path.join(appconfig.base_directory, db_name)
                if not os.path.isfile(abs_path):
                    front, ext = os.path.splitext(abs_path)
                    abs_path = front + ext.lower()

                abs_path = abs_path.replace("\\", "/")

                if appconfig.rename_exported and not hash_name == 'sha1b32':  # the default is sha1b32
                    # sigh. we have to now get the appropriate hash value from the database and do trickery based on that
                    # we know the file id, so we can get the hash for the corresponding hash_type from the database
                    # since we also know the hash_id

                    new_hash = get_hash_from_hash_id_and_file_id(appconfig, hash_id, value)

                    out_path = build_new_out_path(export_directory, new_hash, db_name)
                else:
                    out_path = os.path.join(export_directory, db_name.replace("\\", "/"))

               # print("abs_path is {}".format(abs_path))
              #  print("out_path is {}".format(out_path))

                file_count += 1

                print("[{:,d}/{:,d}] Copying '{}' to '{}'\n".format(file_count,len(existing_hash_list), abs_path, out_path))
                copy_file(abs_path, log_file, out_path)  # TODO Error handling here




    hash_file.close()
    log_file.close()

    if appconfig.zip_exported:

        zip_name = os.path.join(appconfig.export_directory,
                                "Exported " + hash_name + " " + datetime_string + ".zip")
        print("\t\tZipping files to '{}'\n".format(zip_name))
        z_file = zipfile.ZipFile(zip_name, "w")

        for dirpath, dirnames, filenames in os.walk(export_directory):
            for filename in filenames:
                full_name = os.path.join(export_directory, dirpath, filename)
                if full_name.endswith("txt"):
                    archive_name = os.path.basename(full_name)
                else:
                    parts = full_name.split("\\")
                    archive_name = "\\".join(str(parts[-3:]))

                z_file.write(full_name, archive_name)
        z_file.close()

        print("\t\tRemoving '{} since export was zipped to {}...'\n".format(export_directory, zip_name))
        shutil.rmtree(export_directory)

    print("\n\t\tSaw {:,d} {} hashes in '{}'. Files found: {:,d}. See '{}' for details.".format(hash_count, hash_name,
                                                                                                file_name, found_files,
                                                                                                log_name))


def get_stats(appconfig, stats_level):
    # total files
    # total size

    total_store_files = 0
    total_store_size = 0

    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    c.execute("SELECT COUNT(fileID) FROM files")

    row = c.fetchone()

    total_db_files = row[0] or 0

    c.execute("SELECT sum(filesize) FROM files")

    row = c.fetchone()

    total_db_size = row[0] or 0

    conn.close()

    if stats_level == 'full':
        for r, d, files in os.walk(os.path.join(appconfig.base_directory, "files")):
            total_store_files += len(files)
            for file in files:
                total_store_size += os.path.getsize(os.path.join(r, file))

    return total_db_files, total_db_size, total_store_files, total_store_size


def bytes_to_human(byte_value, to, bsize=1024):
    """convert byte_value to megabytes, etc.
       sample code:
           print('mb= ' + str(bytesto(314575262000000, 'm')))

       sample output:
           mb= 300002347.946
    """

    if byte_value is None:
        return float(0)

    a = {'k': 1, 'm': 2, 'g': 3, 't': 4, 'p': 5, 'e': 6}
    r = float(byte_value)
    for i in range(a[to]):
        r /= bsize

    return r


def dump_stats(appconfig, print_stats):
    print("\n*** Database statistics ***\n")

    if print_stats == 'full':
        print("\t *** Please be patient while file store statistics are calculated. This may take a while! ***\n")

    (total_db_files, total_db_size, total_store_files, total_store_size) = get_stats(appconfig, print_stats)

    print("Total files in database: {:,d}".format(total_db_files))
    print("Total size of files in database: {:,d} bytes ({:,f} MB, {:,f} GB, {:,f} TB)\n".format(total_db_size,
                                                                                                 bytes_to_human(
                                                                                                     total_db_size,
                                                                                                     'm'),
                                                                                                 bytes_to_human(
                                                                                                     total_db_size,
                                                                                                     'g'),
                                                                                                 bytes_to_human(
                                                                                                     total_db_size,
                                                                                                     't')))

    if print_stats == 'full':
        print("Total files in file store: {:,d}".format(total_store_files))
        print("Total size of files in file store: {:,d} bytes ({:,f} MB, {:,f} GB, {:,f} TB)\n".format(total_store_size,
                                                                                                       bytes_to_human(
                                                                                                           total_store_size,
                                                                                                           'm'),
                                                                                                       bytes_to_human(
                                                                                                           total_store_size,
                                                                                                           'g'),
                                                                                                       bytes_to_human(
                                                                                                           total_store_size,
                                                                                                           't')))

        count_discrepancy = False
        size_discrepancy = False

        if not total_db_files == total_store_files:
            count_discrepancy = True

        if not total_db_size == total_store_size:
            size_discrepancy = True

        if size_discrepancy or count_discrepancy:
            print("\n*** WARNING ***")

        if size_discrepancy:
            print(
                "There is a discrepancy between the size of files in the database ({:,d}) and the file store ({:,d})! Delta: {:,d} bytes".format(
                    total_db_size, total_store_size, total_db_size - total_store_size))

        if count_discrepancy:
            print(
                "There is a discrepancy between the number of files in the database ({:,d}) and the file store ({:,d})! Delta: {:,d}".format(
                    total_db_files, total_store_files, total_db_files - total_store_files))

        if size_discrepancy or count_discrepancy:
            print("**It is recommended to use the --verify switch to correct this.")
        else:
            print("Database and file store appear to be in sync!\n\n")


def check_db_to_fs(appconfig):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    c.execute("SELECT fileid, filepath FROM files ORDER BY filepath")

    bad_files = []

    for row in c:
        full_path = os.path.join(appconfig.base_directory, row[1]).lower()
        if not os.path.isfile(full_path):
            bad_files.append(row[0])
            print("\t{} is in database but does not exist in file store!".format(full_path))

    conn.close()

    return bad_files


def get_files_from_db(appconfig):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()
    c.execute("SELECT filepath FROM files")

    file_names = []

    for row in c:
        file_names.append(row[0])

    conn.close()

    return file_names


def check_fs_to_db(appconfig):
    bad_files = []

    db_file_names = get_files_from_db(appconfig)

    for r, d, files in os.walk(os.path.join(appconfig.base_directory, "files")):
        for file in files:
            full_path = os.path.join(r, file)
            db_path = full_path.replace(appconfig.base_directory, "")
            db_path = db_path[1:]

            if not db_path in db_file_names:
                bad_files.append(full_path)
                print("\t{} is in file store but does not exist in database!".format(full_path))

    return bad_files


def get_fileid_from_fileinfo(appconfig, fileinfo):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()

    hashid = get_hash_id_from_hash_name(appconfig, 'sha1b32')

    c.execute("SELECT fileid FROM FILEHASHES WHERE hashID = ? AND filehash = ?;",
              (hashid, fileinfo['hashes']['sha1b32']))

    row = c.fetchone()

    conn.close()

    return row[0]


def delete_files_from_db(appconfig, files):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()

    sql = "DELETE FROM FILEHASHES WHERE fileID in ({})".format(
        ', '.join('?' for _ in list(files)))

    c.execute(sql, files)

    sql = "DELETE FROM files WHERE fileID in ({})".format(
        ', '.join('?' for _ in list(files)))

    c.execute(sql, files)

    conn.commit()

    conn.close()


def delete_file_from_db(appconfig, fileinfo):
    conn = sqlite3.connect(appconfig.database_file)
    c = conn.cursor()

    fileid = get_fileid_from_fileinfo(appconfig, fileinfo)

    c.execute("DELETE FROM filehashes WHERE fileid = ?;", (fileid,))
    conn.commit()

    c.execute("DELETE FROM files WHERE fileid = ?;", (fileid,))
    conn.commit()

    conn.close()


def verify(appconfig):
    print("*** File manager verification ***\n")

    print("Beginning stage 1 (comparing database against file store)...")
    db_to_fs_bad = check_db_to_fs(appconfig)

    if len(db_to_fs_bad) == 0:
        print("Stage 1 complete. No inconsistencies detected between database and file system.")

    print("\nBeginning stage 2 (comparing file store against database)...")
    fs_to_db_bad = check_fs_to_db(appconfig)

    if len(fs_to_db_bad) == 0:
        print("Stage 2 complete. No inconsistencies detected between file system and database.")

    if len(fs_to_db_bad) == 0 and len(db_to_fs_bad) == 0:
        print("\n\nNo inconsistencies detected!")
    else:
        # we have to fix things
        print("\n\nFound {:,d} database and {:,d} file system inconsistencies.".format(len(db_to_fs_bad),
                                                                                       len(fs_to_db_bad)))

        fix_it = input("\nDo you want to fix these issues? [Y|n]: ")

        if not fix_it.lower() == 'n':
            print("\nDeleting bad records from database...", end='')
            delete_files_from_db(appconfig, db_to_fs_bad)

            print("Deleted {:,d} records from database!".format(len(db_to_fs_bad)))

            # set up a clean staging area for files to be imported from
            verify_directory = os.path.join(appconfig.base_directory, "verify")

            if os.path.isdir(verify_directory):
                shutil.rmtree(verify_directory)

            os.mkdir(verify_directory)

            print("Adding files to database...")
            for file in fs_to_db_bad:
                fileinfo = get_file_data(file)

                if file_exists_in_database(appconfig, fileinfo):
                    # nuke it to be clean
                    delete_file_from_db(appconfig, fileinfo)

                # move each file to a staging directory, then call import work on it. done
                head, tail = os.path.split(file)

                to_file = os.path.join(verify_directory, tail)

                unique_prefix = 0

                while os.path.isfile(to_file):
                    # file exists, so get a unique name
                    to_file = os.path.join(verify_directory, str(unique_prefix) + "_" + tail)
                    unique_prefix += 1

                shutil.move(file, to_file)

            (files_added_to_database, total_files, files_deleted, files_copied, files_with_duplicate_hashes,
             files_with_invalid_extensions) = import_files_work(appconfig, verify_directory)

            shutil.rmtree(verify_directory)

            print("\nAdded {:,d} files to database!".format(files_added_to_database))

            print("\n\n*** Repair complete! ***")


def main():
    parser = argparse.ArgumentParser(
        description="""File manager that can import files,
                        export file sets based on a list of hashes, export files NOT in a list, etc.""", epilog="""
                        This program can be used to manage files of any type. Before use, adjust the value of
                        'extensions' at the top of the file. Only files having an extension in this set will be
                        imported. A list of files that weren't imported will be documented in a log file when
                        the import operation finishes.
                        """)

    parser.add_argument("base_directory", help="""The root directory where files
                                                will live. This is also where the database of file info will
                                                be created. Enclose directories with spaces in double quotes.
                                                This should be the first argument provided.
                                                """)

    parser.add_argument("--print_stats", choices=['lite', 'full'], help="""'lite' will produce statistics from
    information in the database only. 'full' will look at both the database and file store.
        """)

    parser.add_argument("--verify", action="store_true", help="""Perform consistency check.
     Stage 1 is verifying what is in the database against what is in the file store.
     Stage 2 is verifying what is in the file store against the database.
     When comparison is complete, the results are displayed and, if any issues are found,
     options presented to correct any inconsistencies.
            """)

    import_group = parser.add_argument_group('Import options', 'These options determine how files are imported')
    import_group.add_argument(
        "--import_from", help="""List of comma separated directories to import
                                files from. Enclose directories with spaces in double quotes. Directories should
                                NOT have trailing slashes (i.e. C:\\foo is OK, but C:\\bar\\ is NOT OK
                                """, metavar='PATHS_TO_IMPORT_FROM')
    import_group.add_argument(
        "--delete_existing", choices=['yes', 'simulate'], help="""When importing, delete source files if
                                                        they already exist in file store. If set to 'simulate' files
                                                         will not actually be deleted. This is useful to see what
                                                         would happen as a result of using this flag without actually
                                                         deleting files.
                                                        """)

    import_group.add_argument(
        "--delete_empty_directories", choices=['yes', 'simulate'], help="""When importing, delete any empty directories found.
                                                        If set to 'simulate' directories will not actually be deleted.
                                                        """)

    import_group.add_argument("--copy_new_destination", help="""The directory to copy any newly imported files into.
                                                    No renaming of files (except when conflicts exist) will be done.
                                                    If directory name has spaces, enclose it in double quotes
                                                    """, metavar='PATH_TO_DIRECTORY')

    generate_group = parser.add_argument_group('Generate hash list options',
                                               'These options determine how hash lists are generated')

    generate_group.add_argument("--generate_hash_list", help="""Creates a CSV file of all hashes in the database. Also
                                                    includes the relative path to the file. The file will be saved to
                                                    the file manager's base directory
                                                    """, choices=['all', 'ed2k', 'md4', 'md5', 'sha1b16', 'sha1b32'])

    generate_group.add_argument("--suppress_file_info", help="""When true, prevents relative file path and file size
                                                    from being included in the hash list. This is handy to generate
                                                    hash lists to import into X-Ways Forensics, etc.
                                                    """, action="store_true")

    export_group = parser.add_argument_group('Export options',
                                             'These options allow for exporting files in several ways.')

    # because crazy people may try to do both at once...
    export_group_exclusive = export_group.add_mutually_exclusive_group()

    export_group_exclusive.add_argument("--export_existing", help="""Export a copy of files in PATH_TO_TEXT_FILE to
                                                    --export_directory. The first line of the file should
                                                    be the hash type to query: md5, sha1b16, sha1b32, ed2k, or md4,
                                                    followed by one hash per line. Enclose paths with spaces
                                                    in double quotes.
                                                    """, metavar='PATH_TO_TEXT_FILE')

    export_group_exclusive.add_argument("--export_delta", help="""Export a copy of files
                                    NOT in PATH_TO_TEXT_FILE to --export_directory. The first line of the file should
                                                    be the hash type to query: md5, sha1b16, sha1b32, ed2k, or md4,
                                                    followed by one hash per line. Enclose paths with spaces
                                                    in double quotes.
                                                    This is useful to synchronize two different file manager instances
                                                    by 1) using --generate_hash_list on one instance and then 2)
                                                    using this option on the file from step 1. The resultant files
                                                    can then be imported into the instance from step 1.
                                                    """, metavar='PATH_TO_TEXT_FILE')

    export_group.add_argument("--export_directory", help="""The target directory when using --export_files_in_list or
                                                    --export_files_not_in_list options. Enclose directories with spaces
                                                    in double quotes.
                                                    """, metavar='PATH_TO_DIRECTORY')

    export_group.add_argument("--rename", help="""When true, all exported files will be renamed to match
                                                    the hash type from the provided file listing.
                                                    """, action="store_true")

    export_group.add_argument("--zip", help="""When true, all exported files will be added to a zip
                                                    archive in --export_directory.
                                                    """, action="store_true")

    # this stores our application parameters so it can get passed around to functions
    appconfig = ApplicationConfiguration()

    args = parser.parse_args()

    if args.delete_existing:
        appconfig.delete_existing = args.delete_existing

    if args.delete_empty_directories:
        appconfig.delete_empty_directories = args.delete_empty_directories

    if args.copy_new_destination:
        appconfig.copy_new_destination = args.copy_new_destination

    if args.base_directory:
        appconfig.base_directory = args.base_directory
        setup_base_directory(appconfig.base_directory)

    appconfig.database_file = os.path.join(appconfig.base_directory, appconfig.database_name)

    print('\n\n')

    init_db(appconfig)

    # Process things in a sane order so things later down the list of options are as complete as possible

    if args.verify:
        verify(appconfig)

    if args.import_from:  # since at least something was passed to this argument, lets try to import
        if extensions.intersection(auto_delete_extensions):
            print(
                "Cannot import files as there is at least one extension in common between 'extensions' and 'auto_delete_extensions: {}".format(
                    ", ".join(extensions.intersection(auto_delete_extensions))))
        else:
            directories = args.import_from.split(",")
            import_files(appconfig, directories)

    if args.generate_hash_list:
        (files_processed, hash_path) = generate_hash_list(appconfig, args.generate_hash_list, args.suppress_file_info)
        if files_processed:
            print("\n\nHashes for {} files have been exported to '{}'\n".format(files_processed, hash_path))
        else:
            print("\n\nNothing to export! The database is empty!\n")

    if args.export_existing or args.export_delta:
        if args.export_directory:
            appconfig.export_directory = os.path.normpath(args.export_directory)

            print("\tExport directory set to: {}".format(appconfig.export_directory))

            if not os.path.exists(appconfig.export_directory):
                print("\tExport directory does not exist. Creating...")
                os.makedirs(appconfig.export_directory)

            if args.rename:
                appconfig.rename_exported = True

            if args.zip:
                appconfig.zip_exported = True

            file_name = ""

            if args.export_existing:
                file_name = args.export_existing

            elif args.export_delta:
                file_name = args.export_delta

            if os.path.isfile(file_name):
                export_files(appconfig, bool(args.export_existing), file_name)
            else:
                print("\t{} does not exist! Export cancelled!".format(file_name))

        else:
            print("\t--export_directory must be set when exporting files! Export cancelled.")

            #see whats set in appconfig
            #attrs = vars(appconfig)
            #print('\n'.join("%s: %s" % item for item in attrs.items()))

            # TODO have a built in web mode to allow searching, exporting etc?
            # TODO Add error handling/try catch, etc
            # TODO make backup of SQLite DB on startup (if newer than last)
            # TODO add --purge_files that takes a list of files and cleans file store and DB of those hashes

    if args.print_stats:
        dump_stats(appconfig, args.print_stats)

    if not args.export_delta and not args.export_existing and not args.generate_hash_list and not args.import_from and not args.print_stats and not args.verify:
        print("You didn't ask me to do anything, so here are some statistics:")
        dump_stats(appconfig, 'lite')


if __name__ == '__main__':
    main()
