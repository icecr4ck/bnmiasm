# -*- coding: utf-8 -*-

from future.utils import viewvalues, viewitems

from PySide2.QtGui import QPalette
from PySide2.QtWidgets import QLabel, QHBoxLayout

from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.function import InstructionTextToken, DisassemblyTextLine
from binaryninja.enums import BranchType, InstructionTextTokenType, SymbolType
from binaryninja.types import Symbol
from binaryninjaui import FlowGraphWidget, ViewType, UIActionHandler, UIAction, StatusBarWidget, Menu, ContextMenuManager, FlowGraphHistoryEntry

from miasm.analysis.machine import Machine
from miasm.analysis.simplifier import IRCFGSimplifierCommon, IRCFGSimplifierSSA
from miasm.analysis.data_flow import load_from_int
from miasm.core.bin_stream import bin_stream_str
from miasm.core.graph import DiGraphSimplifier
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp
from miasm.ir.ir import IRBlock, AssignBlock

archs = { "x86":"x86_32", "x86_64":"x86_64", "armv7":"arml", "aarch64":"aarch64l", "mips32":"mips32l", "powerpc":"ppc32b"}

TYPE_GRAPH_IR = 0
TYPE_GRAPH_IRSSA = 1
TYPE_GRAPH_IRSSAUNSSA = 2

def is_addr_ro_variable(bs, addr, size):
    """
    Return True if address at @addr is a read-only variable.
    WARNING: Quick & Dirty
    @addr: integer representing the address of the variable
    @size: size in bits
    """
    try:
        _ = bs.getbytes(addr, size // 8)
    except IOError:
        return False
    return True


class MiasmOptionsWidget(QLabel):

    def __init__(self, parent):
        super(MiasmOptionsWidget, self).__init__(parent)
        self.statusBarWidget = parent

        self.setBackgroundRole(QPalette.Highlight)
        self.setForegroundRole(QPalette.WindowText)
        self.setText(" Options ▾ ")

        self.contextMenuManager = ContextMenuManager(self)

        self.menu = Menu()
        self.actionHandler = UIActionHandler()
        self.registerActions()
        self.addActions()
        self.bindActions()

        self.actionHandler.setChecked("IR graph", True)

    def registerActions(self):
        UIAction.registerAction("IR graph")
        UIAction.registerAction("IR graph (SSA)")
        UIAction.registerAction("IR graph (SSA + unSSA)")
        UIAction.registerAction("Simplify code")
        UIAction.registerAction("Subcalls don't change stack")
        UIAction.registerAction("Load static memory")

    def addActions(self):
        self.menu.addAction("IR graph", "Transformations")
        self.menu.addAction("IR graph (SSA)", "Transformations")
        self.menu.addAction("IR graph (SSA + unSSA)", "Transformations")
        self.menu.addAction("Simplify code", "Options")
        self.menu.addAction("Subcalls don't change stack", "Options")
        self.menu.addAction("Load static memory", "Options")

    def bindActions(self):
        self.actionHandler.bindAction("IR graph", UIAction(self.on_ir_graph))
        self.actionHandler.bindAction("IR graph (SSA)", UIAction(self.on_ssa_simp))
        self.actionHandler.bindAction("IR graph (SSA + unSSA)", UIAction(self.on_unssa_simp))
        self.actionHandler.bindAction("Simplify code", UIAction(self.on_simp))
        self.actionHandler.bindAction("Subcalls don't change stack", UIAction(self.on_dontmodstack))
        self.actionHandler.bindAction("Load static memory", UIAction(self.on_loadmem))

    def mousePressEvent(self, event):
        self.contextMenuManager.show(self.menu, self.actionHandler)

    def enterEvent(self, event):
        self.setAutoFillBackground(True)
        self.setForegroundRole(QPalette.HighlightedText)
        QLabel.enterEvent(self, event)

    def leaveEvent(self, event):
        self.setAutoFillBackground(False)
        self.setForegroundRole(QPalette.WindowText)
        QLabel.leaveEvent(self, event)

    def on_ir_graph(self, uiActionContext):
        action = "IR graph"
        if self.actionHandler.isChecked(action):
            return
        self.actionHandler.setChecked("IR graph (SSA)", False)
        self.actionHandler.setChecked("IR graph (SSA + unSSA)", False)
        self.actionHandler.setChecked(action, True)
        self.statusBarWidget.miasmIRGraphView.type_graph = TYPE_GRAPH_IR

        graph = self.statusBarWidget.miasmIRGraphView.get_graph()
        self.statusBarWidget.miasmIRGraphView.setGraph(graph)


    def on_ssa_simp(self, uiActionContext):
        action = "IR graph (SSA)"
        if self.actionHandler.isChecked(action):
            return
        self.actionHandler.setChecked("IR graph", False)
        self.actionHandler.setChecked("IR graph (SSA + unSSA)", False)
        self.actionHandler.setChecked(action, True)
        self.statusBarWidget.miasmIRGraphView.type_graph = TYPE_GRAPH_IRSSA

        graph = self.statusBarWidget.miasmIRGraphView.get_graph()
        self.statusBarWidget.miasmIRGraphView.setGraph(graph)

    def on_unssa_simp(self, uiActionContext):
        action = "IR graph (SSA + unSSA)"
        if self.actionHandler.isChecked(action):
            return
        self.actionHandler.setChecked("IR graph", False)
        self.actionHandler.setChecked("IR graph (SSA)", False)
        self.actionHandler.setChecked(action, True)
        self.statusBarWidget.miasmIRGraphView.type_graph = TYPE_GRAPH_IRSSAUNSSA

        graph = self.statusBarWidget.miasmIRGraphView.get_graph()
        self.statusBarWidget.miasmIRGraphView.setGraph(graph)

    def on_simp(self, uiActionContext):
        action = "Simplify code"
        action_state = not self.actionHandler.isChecked(action)
        self.statusBarWidget.miasmIRGraphView.simplify = action_state
        self.actionHandler.setChecked(action, action_state)

        graph = self.statusBarWidget.miasmIRGraphView.get_graph()
        self.statusBarWidget.miasmIRGraphView.setGraph(graph)

    def on_dontmodstack(self, uiActionContext):
        action = "Subcalls don't change stack"
        action_state = not self.actionHandler.isChecked(action)
        self.statusBarWidget.miasmIRGraphView.dontmodstack = action_state
        self.actionHandler.setChecked(action, action_state)

        graph = self.statusBarWidget.miasmIRGraphView.get_graph()
        self.statusBarWidget.miasmIRGraphView.setGraph(graph)

    def on_loadmem(self, uiActionContext):
        action = "Load static memory"
        action_state = not self.actionHandler.isChecked(action)
        self.statusBarWidget.miasmIRGraphView.loadmemint = action_state
        self.actionHandler.setChecked(action, action_state)

        graph = self.statusBarWidget.miasmIRGraphView.get_graph()
        self.statusBarWidget.miasmIRGraphView.setGraph(graph)


class MiasmStatusBarWidget(StatusBarWidget):

    def __init__(self, parent):
        super(MiasmStatusBarWidget, self).__init__(parent)

        self.miasmIRGraphView = parent

        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(0,0,0,0)

        self.options = MiasmOptionsWidget(self)
        self.layout.addWidget(self.options)


class MiasmIRGraph(FlowGraph):

    def __init__(self, ircfg):
        super(MiasmIRGraph, self).__init__()
        self.ircfg = ircfg
        
        # Support user annotations for this graph
        self.uses_block_highlights = True
        self.uses_instruction_highlights = True
        self.includes_user_comments = True
        self.allows_patching = True
        self.shows_secondary_reg_highlighting = True

    def populate_nodes(self):
        nodes = {}
        # create nodes for every block in the function
        for irb in viewvalues(self.ircfg.blocks):
            node = FlowGraphNode(self)
            nodes[irb.loc_key] = node
            self.append(node)

        for irb in viewvalues(self.ircfg.blocks):
            if not irb:
                continue

            # add edges for each block
            if irb.dst.is_cond():
                if irb.dst.src1.is_loc() and irb.dst.src1.loc_key in nodes:
                    nodes[irb.loc_key].add_outgoing_edge(BranchType.TrueBranch, nodes[irb.dst.src1.loc_key])
                if irb.dst.src2.is_loc() and irb.dst.src2.loc_key in nodes:
                    nodes[irb.loc_key].add_outgoing_edge(BranchType.FalseBranch, nodes[irb.dst.src2.loc_key])
            elif irb.dst.is_loc() and irb.dst.loc_key in nodes:
                nodes[irb.loc_key].add_outgoing_edge(BranchType.UnconditionalBranch, nodes[irb.dst.loc_key])
            
            lines = []
            irb_token = self.expr_to_token(ExprLoc(irb.loc_key, irb.dst.size))
            irb_token += [InstructionTextToken(InstructionTextTokenType.TextToken, ":")]
            lines.append(irb_token)
            for assignblk in irb:
                for dst, src in sorted(viewitems(assignblk)):
                    tokens = []
                    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "   "))
                    tokens += self.expr_to_token(dst)
                    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " = "))
                    tokens += self.expr_to_token(src)
                    lines.append(tokens)
                lines.append("")
            lines.pop() # remove last empty line
            nodes[irb.loc_key].lines = lines

    def expr_to_token(self, expr):
        tokens = []
        if isinstance(expr, ExprId):
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, str(expr)))
        elif isinstance(expr, ExprInt):
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(expr), int(expr)))
        elif isinstance(expr, ExprMem):
            tokens.append(InstructionTextToken(InstructionTextTokenType.DataSymbolToken, "@%d" % expr.size))
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "["))
            tokens += self.expr_to_token(expr.ptr)
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "]"))
        elif isinstance(expr, ExprOp):
            if expr.is_infix():
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "("))
                for arg in expr.args:
                    tokens += self.expr_to_token(arg)
                    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " %s " % expr.op))
                tokens.pop() # remove last separation token
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ")"))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.CodeSymbolToken, expr.op))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "("))
                for arg in expr.args:
                    tokens += self.expr_to_token(arg)
                    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
                tokens.pop() # remove last separation token
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ")"))
                
        elif isinstance(expr, ExprLoc):
            if self.ircfg.loc_db.get_location_offset(expr.loc_key):
                tokens.append(InstructionTextToken(InstructionTextTokenType.DataSymbolToken, self.ircfg.loc_db.pretty_str(expr.loc_key), self.ircfg.loc_db.get_location_offset(expr.loc_key)))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.DataSymbolToken, self.ircfg.loc_db.pretty_str(expr.loc_key)))
        elif isinstance(expr, ExprCond):
            tokens += self.expr_to_token(expr.cond)
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "?("))
            tokens += self.expr_to_token(expr.src1)
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
            tokens += self.expr_to_token(expr.src2)
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ")"))
        elif isinstance(expr, ExprSlice):
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "("))
            tokens += self.expr_to_token(expr.arg)
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ")"))
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "["))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(expr.start), expr.start))
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ":"))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(expr.stop), expr.stop))
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "]"))
        elif isinstance(expr, ExprCompose):
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "{"))
            for idx, arg in expr.iter_args():
                tokens += self.expr_to_token(arg)
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(idx), idx))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))
                tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(idx+arg.size), idx+arg.size))
                tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, ", "))
            tokens.pop() # remove last separation token
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "}"))
        else:
            raise("Expression not handled: %s" % type(expr))
        return tokens

    def update(self):
        return MiasmIRGraph(self.ircfg)


class MiasmIRGraphView(FlowGraphWidget):

    def __init__(self, parent, data):
        self.data = data
        self.function = data.entry_function

        self.simplify = False
        self.dontmodstack = False
        self.loadmemint = False
        self.type_graph = TYPE_GRAPH_IR

        if self.function is None:
            graph = None
        else:
            graph = self.get_graph()
        super(MiasmIRGraphView, self).__init__(parent, data, graph)

    def get_graph(self):
        simplify = self.simplify
        dontmodstack = self.dontmodstack
        loadmemint = self.loadmemint
        type_graph = self.type_graph

        bin_str = ""
        for s in self.data.segments:
            bin_str += self.data.read(s.start, len(s))
            # add padding between each segment
            if s.end != self.data.end:
                bin_str += '\x00'*(((s.end|0xfff)+1)-s.end)

        bs = bin_stream_str(input_str=bin_str, base_address=self.data.start)
        machine = Machine(archs[self.data.arch.name])
        mdis = machine.dis_engine(bs)

        asmcfg = mdis.dis_multiblock(self.function.start)
        entry_points = set([mdis.loc_db.get_offset_location(self.function.start)])
        
        
        class IRADelModCallStack(machine.ira):
            def call_effects(self, addr, instr):
                assignblks, extra = super(IRADelModCallStack, self).call_effects(addr, instr)
                if not dontmodstack:
                    return assignblks, extra
                out = []
                for assignblk in assignblks:
                    dct = dict(assignblk)
                    dct = {
                        dst:src for (dst, src) in viewitems(dct) if dst != self.sp
                    }
                    out.append(AssignBlock(dct, assignblk.instr))
                return out, extra


        ir_arch = IRADelModCallStack(mdis.loc_db)
        ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

        for irb in list(viewvalues(ircfg.blocks)):
            irs = []
            for assignblk in irb:
                new_assignblk = {
                    expr_simp(dst): expr_simp(src)
                    for dst, src in viewitems(assignblk)
                }
                irs.append(AssignBlock(new_assignblk, instr=assignblk.instr))
            ircfg.blocks[irb.loc_key] = IRBlock(irb.loc_key, irs)

        head = list(entry_points)[0]

        if simplify:
            ircfg_simplifier = IRCFGSimplifierCommon(ir_arch)
            ircfg_simplifier.simplify(ircfg, head)

        if type_graph == TYPE_GRAPH_IR:
            return MiasmIRGraph(self.add_names(ircfg))


        class IRAOutRegs(machine.ira):
            def get_out_regs(self, block):
                regs_todo = super(IRAOutRegs, self).get_out_regs(block)
                out = {}
                for assignblk in block:
                    for dst in assignblk:
                        reg = self.ssa_var.get(dst, None)
                        if reg is None:
                            continue
                        if reg in regs_todo:
                            out[reg] = dst
                return set(viewvalues(out))


        # Add dummy dependency to uncover out regs affectation
        for loc in ircfg.leaves():
            irblock = ircfg.blocks.get(loc)
            if irblock is None:
                continue
            regs = {}
            for reg in ir_arch.get_out_regs(irblock):
                regs[reg] = reg
            assignblks = list(irblock)
            new_assiblk = AssignBlock(regs, assignblks[-1].instr)
            assignblks.append(new_assiblk)
            new_irblock = IRBlock(irblock.loc_key, assignblks)
            ircfg.blocks[loc] = new_irblock


        class CustomIRCFGSimplifierSSA(IRCFGSimplifierSSA):
            def do_simplify(self, ssa, head):
                modified = super(CustomIRCFGSimplifierSSA, self).do_simplify(ssa, head)
                if loadmemint:
                    modified |= load_from_int(ssa.graph, bs, is_addr_ro_variable)
                return modified

            def simplify(self, ircfg, head):
                ssa = self.ircfg_to_ssa(ircfg, head)
                ssa = self.do_simplify_loop(ssa, head)

                if type_graph == TYPE_GRAPH_IRSSA:
                    ret = ssa.graph
                elif type_graph == TYPE_GRAPH_IRSSAUNSSA:
                    ircfg = self.ssa_to_unssa(ssa, head)
                    ircfg_simplifier = IRCFGSimplifierCommon(self.ir_arch)
                    ircfg_simplifier.simplify(ircfg, head)
                    ret = ircfg
                else:
                    raise ValueError("Unknown option")
                return ret


        # dirty patch to synchronize nodes and blocks lists in ircfg
        nodes_to_del = [node for node in ircfg.nodes() if not node in ircfg.blocks]
        for node in nodes_to_del:
            ircfg.del_node(node)

        head = list(entry_points)[0]
        simplifier = CustomIRCFGSimplifierSSA(ir_arch)
        ircfg = simplifier.simplify(ircfg, head)

        return MiasmIRGraph(self.add_names(ircfg))

    def add_names(self, ircfg):
        for name, symbol in viewitems(self.data.symbols):
            # get first item for symbol lists
            if not isinstance(symbol, Symbol):
                symbol = symbol[0]
            loc_key = ircfg.loc_db.get_offset_location(symbol.address)
            if loc_key:
                ircfg.loc_db.add_location_name(loc_key, symbol.short_name)
        
        # set function name
        start_loc_key = ircfg.loc_db.get_offset_location(self.function.start)
        if start_loc_key and not ircfg.loc_db.get_location_names(start_loc_key):
            ircfg.loc_db.add_location_name(start_loc_key, self.function.name)

        return ircfg

    def navigate(self, addr):
        # Find correct function based on most recent use
        block = self.data.get_recent_basic_block_at(addr)
        if block is None:
            # If function isn't done analyzing yet, it may have a function start but no basic blocks
            func = self.data.get_recent_function_at(addr)
        else:
            func = block.function

        if func is None:
            # No function contains this address, fail navigation in this view
            return False

        return self.navigateToFunction(func, addr)

    def navigateToFunction(self, func, addr):
        if func == self.function:
            # Address is within current function, go directly there
            self.showAddress(addr, True)
            return True

        # Navigate to the correct function
        self.function = func
        graph = self.get_graph()
        self.setGraph(graph, addr)
        return True

    def getHistoryEntry(self):
        class MiasmIRGraphHistoryEntry(FlowGraphHistoryEntry):
            def __init__(self, function, simplify, dontmodstack, loadmemint, type_graph):
                super(MiasmIRGraphHistoryEntry, self).__init__()
                self.function = function
                self.simplify = simplify
                self.dontmodstack = dontmodstack
                self.loadmemint = loadmemint
                self.type_graph = type_graph

        result = MiasmIRGraphHistoryEntry(self.function, self.simplify, self.dontmodstack, self.loadmemint, self.type_graph)
        self.populateDefaultHistoryEntry(result)
        return result

    def navigateToHistoryEntry(self, entry):
        if hasattr(entry, 'function') and hasattr(entry, 'type_graph'):
            self.function = entry.function
            self.simplify = entry.simplify
            self.dontmodstack = entry.dontmodstack
            self.loadmemint = entry.loadmemint
            self.type_graph = entry.type_graph

            graph = self.get_graph()
            self.setGraph(graph)
        super(MiasmIRGraphView, self).navigateToHistoryEntry(entry)

    def getStatusBarWidget(self):
        return MiasmStatusBarWidget(self)


class MiasmIRGraphViewType(ViewType):

    def __init__(self, do_simplify=False, do_ssa=False, do_ssaunssa=False):
        super(MiasmIRGraphViewType, self).__init__("Miasm IR Graph", "Miasm IR Graph")

    def getPriority(self, data, filename):
        if data.executable:
            return 1
        return 0

    def create(self, data, view_frame):
        return MiasmIRGraphView(view_frame, data)


ViewType.registerViewType(MiasmIRGraphViewType())
