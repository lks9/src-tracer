import re

from clang.cindex import Index, CursorKind


class Instrumenter:

    def __init__(self, cursor):
        self.cursor = cursor
        self._init_db()
        # initialise the next func_num by taking the max func_num in db + 1
        func_num, = self.cursor.execute("SELECT MAX(num) FROM automatic_lookup").fetchone()
        if func_num is None:
            # add the reserve func num 0 to the db
            self.cursor.execute("INSERT INTO automatic_lookup VALUES (0, null, 0, null)")
            self.cursor.execute("INSERT INTO manual_lookup VALUES (0, null, 0)")
            self.func_num = 1
        else:
            self.func_num = func_num + 1

        self.ifs = []
        self.loops = []
        self.switchis = []
        self.check_locations = []

        self.annotations = {}

    def _init_db(self):
        self.cursor.execute('''
                    CREATE TABLE IF NOT EXISTS automatic_lookup
                        (
                            num     INT     PRIMARY KEY,
                            file    TEXT,
                            line    INT,
                            name    TEXT
                        )
                            ''')
        self.cursor.execute('''
                    CREATE TABLE IF NOT EXISTS manual_lookup
                        (
                            num      INT,
                            pre_file TEXT,
                            offset   INT,
                            PRIMARY KEY (pre_file, offset)
                        )
                            ''')

    def filename(self, location):
        filename = location.file.name
        if filename not in self.annotations:
            with open(filename, "rb") as f:
                content = f.read()
            self.annotations[filename] = {"content": content}
            self.annotations[filename][0] = b'#include "src_tracer.h"\n'
        return filename

    def orig_file_and_line(self, location):
        filename = self.filename(location)
        line_no = 0

        content = self.annotations[filename]["content"]
        up_to = content[:location.offset]
        loc_line = re.compile(rb'\# ([0-9]+) "([^"]+)"')
        for line in up_to.splitlines():
            line_no += 1
            m = loc_line.match(line)
            if m:
                line_no = int(m.group(1))
                filename = (m.group(2)).decode("utf-8")
        return (filename, line_no)

    #TODO: change name
    def func_num_app(self, node):
        pre_filename = self.filename(node.extent.start)
        (file, line) = self.orig_file_and_line(node.extent.start)
        offset = node.extent.start.offset
        func_num_auto = self.cursor.execute("SELECT num FROM automatic_lookup WHERE line=? and file=?", (line, file)).fetchone()
        func_num_manu = self.cursor.execute("SELECT num FROM manual_lookup WHERE pre_file=? and offset=?", (pre_filename, offset)).fetchone()
        if func_num_manu is None:
            data = (func_num_auto[0] if func_num_auto is not None else self.func_num, pre_filename, offset)
            self.cursor.execute("INSERT INTO manual_lookup VALUES(?,?,?)", data)
        if func_num_auto is not None:
            return func_num_auto[0]
        data = (self.func_num, file, line, node.spelling)
        self.cursor.execute("INSERT INTO automatic_lookup VALUES(?,?,?,?)", data)
        func_num = self.func_num
        self.func_num = self.func_num + 1
        return func_num

    def add_annotation(self, annotation, location, add_offset=0):
        offset = location.offset + add_offset
        filename = self.filename(location)
        if offset not in self.annotations[filename]:
            self.annotations[filename][offset] = b""
        self.annotations[filename][offset] += annotation

    def prepent_annotation(self, annotation, location, add_offset=0):
        offset = location.offset + add_offset
        filename = self.filename(location)
        if offset not in self.annotations[filename]:
            self.annotations[filename][offset] = annotation
        else:
            self.annotations[filename][offset] = annotation + self.annotations[filename][offset]

    def visit_function(self, node):
        body = None
        for child in node.get_children():
            if child.kind == CursorKind.COMPOUND_STMT:
                body = child
        if not body:
            return
        func_num = self.func_num_app(node)
        if not self.check_location(body.extent.start, [b"{"]):
            print("Check location failed for function " + node.spelling)
            return
        self.add_annotation(b" _FUNC(" + bytes(hex(func_num), "utf-8") + b") ", body.extent.start, 1)

        # handle returns
        for descendant in node.walk_preorder():
            if descendant.kind == CursorKind.RETURN_STMT:
                self.add_annotation(b"_FUNC_RETURN ", descendant.extent.start)
        self.add_annotation(b"_FUNC_RETURN ", node.extent.end, -1)

        # special treatment for main function
        if node.spelling == "main":
            # print('Log trace to "' + filename + '.trace"')
            token_end = None
            for token in node.get_tokens():
                if token.spelling == "main":
                    token_end = token.extent.end
            self.add_annotation(b"_original", token_end)
            filename = self.filename(node.extent.end)
            new_main = b' _MAIN_FUN("' + bytes(filename, "utf-8") + b'.trace") '
            self.add_annotation(new_main, node.extent.end)

    def get_content(self, start, end):
        filename = self.filename(start)
        content = self.annotations[filename]["content"]
        return content[start.offset: end.offset]

    def find_next_semi(self, location):
        filename = self.filename(location)
        content = self.annotations[filename]["content"]
        # either there was a '}' and no ';'
        if content[location.offset-1] in b'}':
            return -1
        # or we have to find the next ';'
        i = -1
        while content[location.offset + i] not in b';':
            i += 1
        return i

    def find_next_colon(self, location):
        filename = self.filename(location)
        content = self.annotations[filename]["content"]
        i = 0
        while content[location.offset + i] not in b':':
            i += 1
        return i

    def find_last_else(self, location):
        """
        Better than find_next_semi if we have the else keyword.
        """
        filename = self.filename(location)
        content = self.annotations[filename]["content"]
        i = -1
        while b"else" not in content[location.offset+i:location.offset]:
            i -= 1
        return i

    def check_location(self, location, strlist):
        filename = self.filename(location)
        try:
            content = self.annotations[filename]["content"]
            offset = location.offset
            if (offset, strlist) in self.check_locations:
                # already checked, prevent double annotations!
                return False
            else:
                self.check_locations.append((offset, strlist))
            for s in strlist:
                if s == content[offset:offset+len(s)]:
                    return True
            return False
        except:
            return False

    def check_const_method(self, node):
        # for some reason, this does not give all const methods
        if node.is_const_method():
            return True
        try:
            children = [c for c in node.get_children()]
            body = children[-1]
            low = node.extent.start
            high = body.extent.start
            if b"constexpr" in self.get_content(low, high):
                return True
        except:
            pass
        return False

    def visit_if(self, node):
        self.ifs.append(node)
        if not self.check_location(node.extent.start, [b"if"]):
            print("Check location failed for if")
            return
        children = [c for c in node.get_children()]

        # hack for C++
        if children[1].extent.start.offset < children[0].extent.end.offset:
            children.pop(1)

        if len(children) < 2 or len(children) > 3:
            print(self.get_content(node.extent.start, node.extent.end))
            raise Exception

        if_body = children[1]
        if len(children) == 3:
            else_body = children[2]
        else:
            else_body = None

        if if_body.kind == CursorKind.COMPOUND_STMT:
            if else_body:
                if else_body.kind == CursorKind.COMPOUND_STMT:
                    self.prepent_annotation(b" _IF ", if_body.extent.start, 1)
                    self.prepent_annotation(b" _ELSE ", else_body.extent.start, 1)
                else:
                    else_semi_off = self.find_next_semi(else_body.extent.end)
                    self.prepent_annotation(b" _IF ", if_body.extent.start, 1)
                    self.prepent_annotation(b" { _ELSE ", else_body.extent.start)
                    self.prepent_annotation(b" } ", else_body.extent.end, else_semi_off + 1)
            else:
                self.prepent_annotation(b" _IF ", if_body.extent.start, 1)
                self.prepent_annotation(b" else { _ELSE } ", node.extent.end)
        else:
            if else_body:
                else_minus_off = self.find_last_else(else_body.extent.start)
                if else_body.kind == CursorKind.COMPOUND_STMT:
                    self.prepent_annotation(b" { _IF ", if_body.extent.start)
                    self.prepent_annotation(b" } ", else_body.extent.start, else_minus_off)
                    self.prepent_annotation(b" _ELSE ", else_body.extent.start, 1)
                else:
                    else_semi_off = self.find_next_semi(else_body.extent.end)
                    self.prepent_annotation(b" { _IF ", if_body.extent.start)
                    self.prepent_annotation(b" } ", else_body.extent.start, else_minus_off)
                    self.prepent_annotation(b" { _ELSE ", else_body.extent.start)
                    self.prepent_annotation(b" } ", else_body.extent.end, else_semi_off + 1)
            else:
                if_semi_off = self.find_next_semi(if_body.extent.end)
                self.prepent_annotation(b" { _IF ", if_body.extent.start)
                self.prepent_annotation(b" } else { _ELSE } ", if_body.extent.end, if_semi_off + 1)

    # the ?: ternary operator
    def visit_conditional_op(self, node):
        self.ifs.append(node)
        children = [c for c in node.get_children()]
        condition = children[0]
        self.add_annotation(b" _CONDITION(", condition.extent.start)
        self.add_annotation(b") ", condition.extent.end)

    def visit_loop(self, node):
        loop_id = bytes(hex(len(self.loops)), "utf-8")
        self.loops.append(node)
        if not self.check_location(node.extent.start, [b"for", b"while", b"do"]):
            print("Check location failed for loop")
            return
        body = None
        for child in node.get_children():
            if (child.kind == CursorKind.COMPOUND_STMT):
                body = child
#        self.add_annotation(b" _LOOP_START(" + loop_id + b") ", node.extent.start)
        if body:
            self.prepent_annotation(b" _LOOP_BODY(" + loop_id + b") ", body.extent.start, 1)
            self.prepent_annotation(b" _LOOP_END(" + loop_id + b") ", node.extent.end)
        else:
            childs = [c for c in node.get_children()]
            if len(childs) >= 2:
                if node.kind == CursorKind.DO_STMT:
                    stmt = childs[0]
                    semi_off = self.find_next_semi(stmt.extent.end)
                    semi_off2 = self.find_next_semi(node.extent.end)
                    self.prepent_annotation(b" { _LOOP_BODY(" + loop_id + b") ", stmt.extent.start)
                    self.prepent_annotation(b" } ", stmt.extent.end, semi_off + 1)
                    self.prepent_annotation(b" _LOOP_END(" + loop_id + b") ", node.extent.end, semi_off2 + 1)
                else:
                    stmt = childs[-1]
                    semi_off = self.find_next_semi(node.extent.end)
                    self.prepent_annotation(b" { _LOOP_BODY(" + loop_id + b") ", stmt.extent.start)
                    self.prepent_annotation(b" } _LOOP_END(" + loop_id + b") ", node.extent.end, semi_off + 1)
            else:
                semi_off = self.find_next_semi(node.extent.end)
                self.prepent_annotation(b" { _LOOP_BODY(" + loop_id + b") } _LOOP_END(" + loop_id + b") ",
                                        node.extent.end, semi_off + 1)

#        # handle returns & gotos
#        for descendant in node.walk_preorder():
#            if (descendant.kind in (CursorKind.RETURN_STMT, CursorKind.GOTO_STMT)):
#                self.add_annotation(b"_LOOP_END(" + loop_id + b") ", descendant.extent.start)

#    def traverse_switch(self, node, switch_id):
#        if node.kind in (CursorKind.CASE_STMT, CursorKind.DEFAULT_STMT):
#            case_id = bytes(hex(self.switch_case_count), "utf-8")
#            if node.kind == CursorKind.CASE_STMT:
#                number_end = [c for c in node.get_children()][0].extent.end
#            else:
#                number_end = node.extent.start
#            try:
#                colon_off = self.find_next_colon(number_end)
#                self.add_annotation(b" _CASE(" + case_id + b", " + switch_id + b") ", number_end, colon_off+1)
#            except IndexError:
#                print(b"Failed to annotate _CASE(" + case_id + b", " + switch_id + b") ")
#            self.switch_case_count += 1
#
#        for child in node.get_children():
#            if (child.kind != CursorKind.SWITCH_STMT):
#                self.traverse_switch(child, switch_id)

    def visit_switch(self, node):
        self.switchis.append(node)
        children = [c for c in node.get_children()]
        if not self.check_location(node.extent.start, [b"switch"]) or len(children) != 2:
            print("Check location failed for switch")
            return
        switch_num = children[0]
        self.add_annotation(b"_SWITCH(", switch_num.extent.start)
        self.add_annotation(b")", switch_num.extent.end, 1)

    def parse(self, filename):
        index = Index.create()
        tu = index.parse(filename)

        root = tu.cursor

        self.traverse(root)

    def annotate_all(self, filename):
        if filename in self.annotations:
            annotation = self.annotations[filename]
            content = annotation["content"]
            # overwrite
            if (b'#include "src_tracer.h"' in content):
                # print("Skipping " + filename + " (already annotated)")
                return False
            # print("Overwriting " + filename + "...")
            prevchar = b' '
            with open(filename, "wb") as f:
                for offset, char_int in enumerate(content):
                    char = char_int.to_bytes(1, "little")
                    if offset in annotation:
                        ann = annotation[offset]
                        try:
                            if prevchar in b' \t\n' and ann[0] in b' ':
                                # skip the first ' ' because there already is a ws
                                ann = ann[1:]
                            if char in b' \t\n' and ann[-1] in b' ':
                                # skip the last ' ' because there already is a ws
                                ann = ann[:-1]
                        except TypeError:
                            print(char, prevchar, ann)
                        f.write(ann)
                    f.write(char)
                    prevchar = char
            return True
        else:
            # print("Skipping " + filename + " (nothing to annotate)")
            return False

    def traverse(self, node, file_scope=True):
        try:
            if node.kind in (CursorKind.FUNCTION_DECL, CursorKind.FUNCTION_TEMPLATE):
                # no recursive annotation
                if "_trace" in node.spelling or "_retrace" in node.spelling:
                    return
                # no instrumentation of C++ constant functions
                if self.check_const_method(node):
                    return
                file_scope = False
                self.visit_function(node)
            elif (node.kind == CursorKind.IF_STMT):
                self.visit_if(node)
            elif (node.kind == CursorKind.CONDITIONAL_OPERATOR):
                # ?: operator
                # if not file_scope:
                if False:
                    self.visit_conditional_op(node)
            elif (node.kind in (CursorKind.WHILE_STMT, CursorKind.FOR_STMT, CursorKind.DO_STMT)):
                self.visit_loop(node)
            elif (node.kind == CursorKind.SWITCH_STMT):
                self.visit_switch(node)
        except:
            print("Failed to annotate a " + str(node.kind))

        for child in node.get_children():
            self.traverse(child, file_scope=file_scope)
