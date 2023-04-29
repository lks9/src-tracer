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
