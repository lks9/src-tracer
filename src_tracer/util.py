import logging

log = logging.getLogger(__name__)

class Util:

    @classmethod
    def get_name(cls, cursor, func_num):
        cursor.execute("SELECT name FROM function_list WHERE rowid=?", (func_num,))
        name = cursor.fetchone()
        if name is None:
            log.error("there is no name (entry) for the func_num (%d)", func_num)
            return None
        return name[0]

    @classmethod
    def get_numbers(cls, cursor, func_name):
        cursor.execute("SELECT rowid FROM function_list WHERE name=?", (func_name,))
        return [func_num[0] for func_num in cursor.fetchall()]
