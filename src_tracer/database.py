import logging
import sqlite3
import os

from typing import List, Tuple

log = logging.getLogger(__name__)

class Database:

    def __init__(self, store_dir, name="function_database.db", path=None):
        if path:
            self.connection = sqlite3.connect(path)
        else:
            db_path = os.path.join(store_dir, name)
            self.connection = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self):
        self._create_table('function_list',
                        [('file', 'TEXT'), ('line', 'INT'), ('name', 'TEXT')],
                        ['file', 'name'])

    def get_name(self, func_num):
        cursor = self.connection.cursor()
        cursor.execute("SELECT name FROM function_list WHERE rowid=?", (func_num,))
        name = cursor.fetchone()
        cursor.close()
        if name is None:
            log.error("there is no name (entry) for the func_num (%d)", func_num)
            return None
        return name[0]

    def get_numbers(self, func_name):
        cursor = self.connection.cursor()
        cursor.execute("SELECT rowid FROM function_list WHERE name=?", (func_name,))
        func_nums = [func_num[0] for func_num in cursor.fetchall()]
        cursor.close()
        return func_nums

    def _create_table(self, table_name: str, colum_name_type: List[Tuple[str, str]], key: List[str]):
        columns = ", ".join([" ".join(col) for col in colum_name_type])
        key_str = ", ".join(key)
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'''
                       CREATE TABLE IF NOT EXISTS {table_name}
                            ( {columns}, PRIMARY KEY ({key_str}) )
                       ''')
        except sqlite3.OperationalError:
            # who knows, perhaps the table was created in another process ???
            pass
        cursor.close()
        self.connection.commit()

    def insert_to_table(self, file, line, name, pre_file=None, offset=None):
        cursor = self.connection.cursor()
        sql = f'''INSERT INTO function_list
                (file, line, name)
                VALUES(?, ?, ?)
                ON CONFLICT DO NOTHING'''
        cursor.execute(sql, (file, line, name))
        cursor.close()
        self.connection.commit()

    def get_number(self, file, name):
        cursor = self.connection.cursor()
        func_num = cursor.execute('''
                                  SELECT rowid
                                  FROM function_list
                                  WHERE file=? and name=?
                                  ''', (file, name)).fetchone()
        cursor.close()
        return func_num[0]

    def close_connection(self):
        self.connection.commit()
        self.connection.close()
