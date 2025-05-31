import re
import os
import sqlite3

from clang.cindex import Index, CursorKind, StorageClass


class Line_Retracer:

    def __init__(self, database,
                 return_instrument=True,
                 exclude=[],
                 output_format="cbmc"):
        """
        Instrument a C compilation unit (pre-processed C source code).
        :param case_instrument: instrument each switch case, not the switch (experimental)
        """
        self.database = database
        self.return_instrument = return_instrument
        self.exclude = exclude
        self.output_format = output_format

        self.ifs = []
        self.loops = []
        self.switchis = []
        self.trys = []
        self.check_locations = []

        self.annotations = {}

        self.ast = {}

    def parse(self, filename):
        index = Index.create()
        tu = index.parse(filename)
        self.ast[filename] = tu

        root = tu.cursor

    def is_funcbody(self, node):
        return node.kind in (CursorKind.FUNCTION_DECL, CursorKind.FUNCTION_TEMPLATE, CursorKind.CXX_METHOD)

    def resolve_function(self, file, line, name):
        if file not in self.ast:
            self.parse(file)
        for node in self.ast[file].cursor.walk_preorder():
            if not self.is_funcbody(node):
                continue
            if node.spelling != name:
                continue
            if node.location.file.name != file:
                continue
            if node.location.line != line:
                continue
            return node
        print("could not resolve " + file + ":" + str(line) + " " + name)
        raise

    def print_start(self, node):
        if self.output_format == "cbmc":
            print()
            print("cbmc " + node.location.file.name
                  + " --function " + node.spelling
                  + " --retrace ", end='')

    def print_end(self, node):
        if self.output_format == "cbmc":
            # new line
            print()
            print()

    def abstract_retrace(self, trace_iter):
        """
        Retrace and print the control flow path in a readible/usable format, depending on the configuration
        """
        self.retrace_function(trace_iter, start=True)

    def print_line(self, file, start, end=None):
        if self.output_format != "lines":
            return
        if file is None or start is None:
            return
        if end is None or start == end:
            print(file + ":" + str(start))
        else:
            print(file + ":" + str(start) + "-" + str(end))

    def print_location(self, node):
        self.print_line(node.location.file.name, node.location.line)

    def print_cbmc(self, number):
        if self.output_format != "cbmc":
            return
        print(str(number), end='')

    def retrace_expr(self, node, trace_iter):
        for child in node.walk_preorder():
            if child.kind == CursorKind.CALL_EXPR:
                self.print_location(node)
                self.retrace_function(trace_iter)

    def has_call(self, node):
        for child in node.walk_preorder():
            if child.kind == CursorKind.CALL_EXPR:
                return True
        return False

    def retrace_node(self, node, trace_iter):
        """
        General method to retrace along a node of any kind
        """
        if node.kind == CursorKind.RETURN_STMT:
            self.retrace_expr(node, trace_iter)
            if self.return_instrument:
                elem = next(trace_iter)
                assert elem.letter == 'R'
            self.print_location(node)
            return True

        elif node.kind == CursorKind.COMPOUND_STMT:
            return self.retrace_block(node, trace_iter)

        elif node.kind == CursorKind.IF_STMT:
            return self.retrace_if(node, trace_iter)

        elif node.kind == CursorKind.WHILE_STMT:
            return self.retrace_while(node, trace_iter)

        elif node.kind == CursorKind.DO_STMT:
            return self.retrace_do(node, trace_iter)

        elif node.kind == CursorKind.FOR_STMT:
            return self.retrace_for(node, trace_iter)

        else:
            self.retrace_expr(node, trace_iter)

        # final print
        self.print_location(node)
        return False

    def retrace_if(self, node, trace_iter):
        childs = [c for c in node.get_children()]
        condition = childs[0]
        body = childs[1]

        self.print_location(condition)
        elem = next(trace_iter)

        if elem.letter == 'I':
            self.print_cbmc(0)
            return self.retrace_node(body, trace_iter)
        elif elem.letter == 'O':
            self.print_cbmc(1)
            if len(childs) == 3:
                else_body = childs[2]
                return self.retrace_node(else_body, trace_iter)
            else:
                return False
        # other letter?
        print(elem)
        raise

    def retrace_while(self, node, trace_iter):
        childs = [c for c in node.get_children()]
        if len(childs) < 2:
            raise
        condition = childs[0]
        body = childs[-1]
        while True:
            self.print_location(condition)
            elem = next(trace_iter)
            if elem.letter == 'I':
                self.print_cbmc(0)
                if self.retrace_node(body, trace_iter):
                    # propagate RETURN_STMT
                    return True
                self.print_cbmc(1)
            elif elem.letter == 'O':
                self.print_cbmc(1)
                return False
            else:
                # other letter?
                raise

    def retrace_do(self, node, trace_iter):
        childs = [c for c in node.get_children()]
        if len(childs) != 2:
            raise
        condition = childs[1]
        body = childs[0]
        branch = False
        while True:
            elem = next(trace_iter)
            if elem.letter == 'I':
                if branch:
                    self.print_cbmc(0)
                if self.retrace_node(body, trace_iter):
                    # propagate RETURN_STMT
                    return True
            elif elem.letter == 'O':
                self.print_cbmc(1)
                return False
            else:
                raise
            self.print_location(condition)
            branch = True

    def retrace_for(self, node, trace_iter):
        childs = [c for c in node.get_children()]
        if len(childs) != 4:
            raise
        initialization = childs[0]
        condition = childs[1]
        update = childs[2]
        body = childs[-1]

        self.print_location(initialization)
        self.retrace_node(initialization, trace_iter)

        while True:
            self.print_location(condition)
            elem = next(trace_iter)
            if elem.letter == 'I':
                self.print_cbmc(0)
                if self.retrace_node(body, trace_iter):
                    # propagate RETURN_STMT
                    return True
                self.print_cbmc(1)
            elif elem.letter == 'O':
                self.print_cbmc(1)
                return False
            else:
                raise
            self.print_location(update)

    def retrace_block(self, node, trace_iter):
        cur_file = node.location.file.name
        cur_start = None
        cur_end = None

        if node.kind != CursorKind.COMPOUND_STMT:
            raise

        for child in node.get_children():
            child_file = child.location.file.name
            child_line = child.location.line
            if cur_file != child_file:
                # file changed, print current lines
                self.print_line(cur_file, cur_start, cur_end)
                cur_file = child_file
                cur_start = child_line
                cur_end = None

            if child.kind in (CursorKind.RETURN_STMT, CursorKind.COMPOUND_STMT, CursorKind.IF_STMT, CursorKind.WHILE_STMT, CursorKind.DO_STMT, CursorKind.FOR_STMT) or self.has_call(child):
                self.print_line(cur_file, cur_start, cur_end)
                if self.retrace_node(child, trace_iter):
                    # propagate RETURN_STMT
                    return True
                cur_start = None
                cur_end = None
                continue

            #print(child.location.file.name, child.location.line, child.kind)
            if cur_start is None:
                cur_start = child_line
            cur_end = child_line
 
        # final print
        self.print_line(cur_file, cur_start, cur_end)
        return False

    def retrace_function(self, trace_iter, start=False):
        elem = next(trace_iter)
        if elem.letter != 'C':
            # function not recorded, skip
            return False
        # print(first)

        (file, line, name) = self.database.from_number(elem.num)
        node = self.resolve_function(file, line, name)
        childs = [c for c in node.get_children()]
        body = childs[-1]

        if start:
            self.print_start(node)
        self.retrace_block(body, trace_iter)
        if start:
            self.print_end(node)
        return False
