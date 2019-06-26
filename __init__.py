from future.utils import viewvalues, viewitems

from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.function import InstructionTextToken, DisassemblyTextLine
from binaryninja.enums import BranchType, InstructionTextTokenType, SymbolType
from binaryninja.types import Symbol
from binaryninjaui import FlowGraphWidget, ViewType

from miasm.analysis.machine import Machine
from miasm.analysis.simplifier import IRCFGSimplifierCommon, IRCFGSimplifierSSA
from miasm.analysis.data_flow import load_from_int
from miasm.core.bin_stream import bin_stream_str
from miasm.core.graph import DiGraphSimplifier
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp
from miasm.ir.ir import IRBlock, AssignBlock

archs = { "x86":"x86_32", "x86_64":"x86_64", "armv7":"arml", "aarch64":"aarch64l", "mips32":"mips32l", "powerpc":"ppc32b"}

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

    def __init__(self, parent, data, do_simplify, do_ssa, do_ssaunssa):
        self.data = data
        self.function = data.entry_function
        self.simplify = do_simplify
        self.ssa = do_ssa
        self.ssaunssa = do_ssaunssa
        if self.function is None:
            graph = None
        else:
            graph = MiasmIRGraph(self.get_ircfg(do_simplify, do_ssa, do_ssaunssa))
        super(MiasmIRGraphView, self).__init__(parent, data, graph)

    def get_ircfg(self, do_simplify, do_ssa, do_ssaunssa):
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

        ir_arch = machine.ira(mdis.loc_db)
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

        if do_simplify:
            ircfg_simplifier = IRCFGSimplifierCommon(ir_arch)
            ircfg_simplifier.simplify(ircfg, head)

        if not (do_ssa or do_ssaunssa):
            return self.add_names(ircfg)


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
                modified |= load_from_int(ssa.graph, bs, is_addr_ro_variable)
                return modified

            def simplify(self, ircfg, head):
                ssa = self.ircfg_to_ssa(ircfg, head)
                ssa = self.do_simplify_loop(ssa, head)

                if do_ssa:
                    ret = ssa.graph
                elif do_ssaunssa:
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
        return self.add_names(self.clean_ircfg(ircfg, head))

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

    def clean_ircfg(self, ircfg, head):
        for leaf_lk in ircfg.heads():
            if leaf_lk != head:
                ircfg.del_block(ircfg.loc_key_to_block(leaf_lk))
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
        graph = MiasmIRGraph(self.get_ircfg(self.simplify, self.ssa, self.ssaunssa))
        self.setGraph(graph, addr)
        return True


class MiasmIRGraphViewType(ViewType):

    def __init__(self, do_simplify=False, do_ssa=False, do_ssaunssa=False):
        self.simplify = do_simplify
        self.ssa = do_ssa
        self.ssaunssa = do_ssaunssa
        if do_simplify:
            super(MiasmIRGraphViewType, self).__init__("Miasm IR graph (simplified)", "Miasm\\IR graph (simplified)")
        elif do_ssa:
            self.simplify = True
            super(MiasmIRGraphViewType, self).__init__("Miasm IR graph (SSA)", "Miasm\\IR graph (SSA)")
        elif do_ssaunssa:
            self.simplify = True
            super(MiasmIRGraphViewType, self).__init__("Miasm IR graph (SSA + UnSSA)", "Miasm\\IR graph (SSA + UnSSA)")
        else:
            super(MiasmIRGraphViewType, self).__init__("Miasm IR graph", "Miasm\\IR graph")

    def getPriority(self, data, filename):
        if data.executable:
            return 1
        return 0

    def create(self, data, view_frame):
        return MiasmIRGraphView(view_frame, data, self.simplify, self.ssa, self.ssaunssa)


ViewType.registerViewType(MiasmIRGraphViewType())
ViewType.registerViewType(MiasmIRGraphViewType(do_simplify=True))
ViewType.registerViewType(MiasmIRGraphViewType(do_ssa=True))
ViewType.registerViewType(MiasmIRGraphViewType(do_ssaunssa=True))
