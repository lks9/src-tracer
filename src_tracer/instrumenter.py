import re
import os
import sqlite3

from clang.cindex import Index, CursorKind, StorageClass


class Instrumenter:

    def __init__(self, database, trace_store_dir, case_instrument=False, boolop_instrument=False,
                 return_instrument=True, inline_instrument=False, main_instrument=True, main_spelling="main",
                 main_close=False, anon_instrument=False,
                 function_instrument=True, inner_instrument=True, call_instrument=True, pointer_call_instrument=False):
        """
        Instrument a C compilation unit (pre-processed C source code).
        :param case_instrument: instrument each switch case, not the switch (experimental)
        """
        self.database = database
        self.trace_store_dir = trace_store_dir
        self.case_instrument = case_instrument
        self.boolop_instrument = boolop_instrument
        self.return_instrument = return_instrument
        self.inline_instrument = inline_instrument
        self.main_instrument = main_instrument
        self.main_spelling = main_spelling
        self.main_close = main_close
        self.anon_instrument = anon_instrument
        self.function_instrument = function_instrument
        self.inner_instrument = inner_instrument
        self.call_instrument = call_instrument
        self.pointer_call_instrument = pointer_call_instrument

        self.ifs = []
        self.loops = []
        self.switchis = []
        self.trys = []
        self.check_locations = []

        self.annotations = {}

    def filename(self, location):
        filename = location.file.name
        if filename not in self.annotations:
            with open(filename, "rb") as f:
                content = f.read()
            self.annotations[filename] = {"content": content}
            self.annotations[filename][0] = b'#include <src_tracer/_after_instrument.h>\n'
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

    def func_num(self, node):
        (file, line) = self.orig_file_and_line(node.extent.start)
        name = node.spelling
        # pre_file = self.filename(node.extent.start)
        # offset = node.extent.start.offset
        try:
            self.database.insert_to_table(file, line, name)
        except sqlite3.OperationalError:
            # perhaps the insert was successful from another process?
            pass
        num = self.database.get_number(file, name)
        return num

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
        if not self.check_location(body.extent.start, [b"{"]):
            print("Check location failed for function " + node.spelling)
            return
        if self.function_instrument:
            if self.anon_instrument:
                self.add_annotation(b" _FUNC(0) ", body.extent.start, 1)
            else:
                func_num = self.func_num(node)
                self.add_annotation(b" _FUNC(" + bytes(hex(func_num), "utf-8") + b") ", body.extent.start, 1)

        # handle returns
        if self.return_instrument:
            for descendant in node.walk_preorder():
                if descendant.kind == CursorKind.RETURN_STMT:
                    self.add_annotation(b"_FUNC_RETURN ", descendant.extent.start)
            self.add_annotation(b"_FUNC_RETURN ", node.extent.end, -1)

        # special treatment for main function
        if self.main_instrument and node.spelling == self.main_spelling:
            if not self.function_instrument:
                # well, we need something to start...
                self.add_annotation(b" _FUNC(0) ", body.extent.start, 1)

            # print('Log trace to ' + self.trace_store_dir)
            try:
                (orig_fname, _) = self.orig_file_and_line(node.extent.start)
            except:
                orig_fname = ""
            trace_fname = "%F-%H%M%S-%%lx-" + os.path.basename(orig_fname) + ".trace"
            trace_path = os.path.join(os.path.abspath(self.trace_store_dir), trace_fname)
            self.prepent_annotation(b' _TRACE_OPEN("' + bytes(trace_path, "utf8") + b'") ', body.extent.start, 1)

            if self.main_close:
                for descendant in node.walk_preorder():
                    if descendant.kind == CursorKind.RETURN_STMT:
                        self.add_annotation(b"_TRACE_CLOSE ", descendant.extent.start)
                self.add_annotation(b"_TRACE_CLOSE ", node.extent.end, -1)

    def get_content(self, start, end):
        filename = self.filename(start)
        content = self.annotations[filename]["content"]
        return content[start.offset: end.offset]

    def node_content(self, node):
        return self.get_content(node.extent.start, node.extent.end)

    def find_next_semi(self, location):
        filename = self.filename(location)
        content = self.annotations[filename]["content"]
        # either '}' or '};'
        if content[location.offset-1] in b'}':
            i = 0
            while (content[location.offset + i] in b' \n\t#'):
                if content[location.offset + i] in b'#':
                    while content[location.offset + i] not in b'\n':
                        i += 1
                i += 1
            if content[location.offset + i] in b';':
                return i
            else:
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

    def search(self, b_str, start, end):
        content = self.get_content(start, end)
        return re.search(b_str, content)

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
            # FIXME might detect false positives!
            children = [c for c in node.get_children()]
            body = children[-1]
            low = node.extent.start
            high = body.extent.start
            if b"constexpr" in self.get_content(low, high):
                return True
        except:
            pass
        return False

    def check_inline_method(self, node):
        try:
            # FIXME might detect false positives!
            children = [c for c in node.get_children()]
            body = children[-1]
            low = node.extent.start
            high = body.extent.start
            return self.search(rb"inline", low, high)
        except:
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

    def visit_binary_op(self, node):
        children = [c for c in node.get_children()]
        if len(children) != 2:
            raise Exception
        left = children[0]
        right = children[1]

        if self.search(rb"(&&|\|\|)", left.extent.end, right.extent.start):
            # found short-circuit && or ||
            self.add_annotation(b" _CONDITION(", left.extent.start)
            self.prepent_annotation(b") ", left.extent.end)

    def visit_loop(self, node):
        loop_id = bytes(hex(len(self.loops)), "utf-8")
        self.loops.append(node)
        if not self.check_location(node.extent.start, [b"for", b"while", b"do"]):
            print("Check location failed for loop")
            return
        if node.kind == CursorKind.DO_STMT:
            childs = [c for c in node.get_children()]
            condition = childs[-1]
            if condition.kind == CursorKind.INTEGER_LITERAL and self.node_content(condition) == b'0':
                # one-time loop with "do { ... } while(0);", no need to instrument
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

    def visit_case(self, node, switch_id, case_id, bits_needed):
        if node.kind == CursorKind.CASE_STMT:
            number_end = [c for c in node.get_children()][0].extent.end
        else:
            number_end = node.extent.start
        try:
            colon_off = self.find_next_colon(number_end)
            self.add_annotation(b" _CASE(" + case_id + b", " + switch_id + b", " + bits_needed + b") ",
                                number_end, colon_off+1)
        except IndexError:
            print(b"Failed to annotate _CASE(" + case_id + b", " + switch_id + b", " + bits_needed + b") ")

    def accumulate_cases(self, node, case_node_list):
        has_default = False
        if node.kind == CursorKind.CASE_STMT:
            case_node_list.append(node)
        elif node.kind == CursorKind.DEFAULT_STMT:
            has_default = True
            case_node_list.append(node)
        for child in node.get_children():
            if (child.kind != CursorKind.SWITCH_STMT):
                res = self.accumulate_cases(child, case_node_list)
                has_default = has_default or res
        return has_default

    def visit_switch(self, node):
        self.switchis.append(node)
        children = [c for c in node.get_children()]
        if not self.check_location(node.extent.start, [b"switch"]) or len(children) != 2:
            print("Check location failed for switch")
            return

        if self.case_instrument:
            # experimental
            switch_id = bytes(hex(len(self.switchis) - 1), "utf-8")
            case_node_list = []
            has_default = self.accumulate_cases(node, case_node_list)
            case_count = len(case_node_list)
            if not has_default:
                # we will add an extra case below
                case_count = case_count + 1
            bits_needed = bytes(hex(int.bit_length(case_count-1)), "utf-8")
            self.add_annotation(b" _SWITCH_START(" + switch_id + b", " + bits_needed + b") ", node.extent.start)

            for case_index in range(len(case_node_list)):
                case_node = case_node_list[case_index]
                case_id = bytes(hex(case_index), "utf-8")
                self.visit_case(case_node, switch_id, case_id, bits_needed)

            # append missing default if necessary
            if not has_default:
                case_id = bytes(hex(case_count - 1), "utf-8")
                self.add_annotation(b" break; default: _CASE(" + case_id + b", "
                                                               + switch_id + b", " + bits_needed + b") ",
                                    node.extent.end, -1)
        else:
            # simpler, default
            switch_num = children[0]
            self.add_annotation(b"_SWITCH(", switch_num.extent.start)
            self.add_annotation(b")", switch_num.extent.end, 1)

    def is_pointer_call(self, node):
        childs = [c for c in node.get_children()]
        normal_call = False
        if len(childs) > 0:
            unexp = childs[0]
            childs = [c for c in unexp.get_children()]
            if len(childs) > 0 and childs[0].kind == CursorKind.DECL_REF_EXPR:
                reference = childs[0]
                target = reference.referenced
                if target and target.kind == CursorKind.FUNCTION_DECL:
                    normal_call = True
        return not normal_call

    def last_call_before(self, node):
        # Returns the last child node (if any) of kind CALL_EXPR that would be
        # evaluated before the evaluation of the current node.
        # Otherwise it returns None.
        childs = [c for c in node.get_children()]
        for c in reversed(childs):
            if c.kind == CursorKind.CALL_EXPR:
                return c
            rec_last = self.last_call_before(c)
            if rec_last is not None:
                return rec_last
        return None

    last_calls = []

    def visit_call(self, node):
        # Some calls need to be anotated
        if node.spelling == "fork":
            self.add_annotation(b"_FORK(", node.extent.start)
            self.prepent_annotation(b")", node.extent.end)
        elif node.spelling in ("setjmp", "sigsetjmp", "_setjmp", "__sigsetjmp"):
            self.add_annotation(b"_SETJMP(", node.extent.start)
            self.prepent_annotation(b")", node.extent.end)
        elif node.spelling in ("exit", "_Exit", "_exit"):
            self.add_annotation(b"(({int exitcode = ", node.extent.start, len(node.spelling))
            self.prepent_annotation(b"; _TRACE_CLOSE; exitcode; }))", node.extent.end)
        elif node.spelling == "abort":
            self.add_annotation(b"_TRACE_CLOSE ", node.extent.start)
        elif self.pointer_call_instrument and self.is_pointer_call(node):
            last_call = self.last_call_before(node)
            if last_call is None:
                self.add_annotation(b"_POINTER_CALL(", node.extent.start)
                self.prepent_annotation(b")", node.extent.end)
            else:
                last_call_type = bytes(last_call.type.spelling, "utf-8")
                self.prepent_annotation(b"_POINTER_CALL_AFTER(" + last_call_type + b", ", last_call.extent.start)
                self.add_annotation(b")", last_call.extent.end)

    def visit_try(self, node):
        childs = [c for c in node.get_children()]
        for i in range(1, len(childs)):
            try_id = bytes(hex(len(self.trys)), "utf-8")
            self.trys.append(node)
            self.prepent_annotation(b" { int _trace_try_idx_" + try_id + b" = ++_trace_setjmp_idx; _TRY ",
                                    node.extent.start)
            self.visit_catch(childs[i], try_id)
            self.prepent_annotation(b" _TRY_END } ", node.extent.end)

    def visit_catch(self, node, try_id):
        childs = [c for c in node.get_children()]
        if len(childs) == 2:
            inside = childs[1]
        elif len(childs) == 1:
            inside = childs[0]
        else:
            print(str(len(childs)) + " childs for catch")
            return
        self.add_annotation(b" _CATCH(_trace_try_idx_" + try_id + b") ", inside.extent.start, 1)

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
            if (b'#include <src_tracer/_after_instrument.h>' in content):
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

    def traverse(self, node, function_scope=False):
        try:
            if node.kind in (CursorKind.FUNCTION_DECL, CursorKind.FUNCTION_TEMPLATE):
                # no recursive annotation
                if "_trace" in node.spelling or "_retrace" in node.spelling:
                    return
                # no instrumentation of C++ constant functions
                if self.check_const_method(node):
                    return
                function_scope = True
                if not self.inline_instrument and self.check_inline_method(node):
                    pass
                else:
                    self.visit_function(node)
            elif not self.inner_instrument:
                pass
            elif node.kind == CursorKind.IF_STMT:
                self.visit_if(node)
            elif node.kind == CursorKind.BINARY_OPERATOR:
                if self.boolop_instrument and function_scope:
                    self.visit_binary_op(node)
            elif node.kind == CursorKind.CONDITIONAL_OPERATOR:
                # ?: operator
                if self.boolop_instrument and function_scope:
                    self.visit_conditional_op(node)
            elif node.kind in (CursorKind.WHILE_STMT, CursorKind.FOR_STMT, CursorKind.DO_STMT):
                self.visit_loop(node)
            elif node.kind == CursorKind.SWITCH_STMT:
                self.visit_switch(node)
            elif node.kind == CursorKind.CALL_EXPR:
                if self.call_instrument:
                    self.visit_call(node)
            elif node.kind == CursorKind.CXX_TRY_STMT:
                if self.call_instrument:
                    self.visit_try(node)
            elif node.type.is_const_qualified():
                # skip constants
                return
            elif node.storage_class == StorageClass.STATIC and node.kind not in (CursorKind.FUNCTION_DECL,
                                                                                 CursorKind.COMPOUND_STMT):
                # something static, not a function declaration smells like a constant expression
                # anyway, static means it cannot be function local
                function_scope = False
        except:
            message = "Failed to annotate a " + str(node.kind)
            raise Exception(message)

        for child in node.get_children():
            self.traverse(child, function_scope=function_scope)
