# -*- coding: utf-8 -*-

import idaapi
import idc
import idautils

import time
import os
import copy
from functools import reduce, wraps

SOURCE_FUNC = {
    'gets': {       # char *gets(char *s);
        'dest': 7,
        'src': 'None',
    },

    'scanf': {      # int scanf(const char *format, ...);
        'dest': 6,
        'src': 'None',
    },

    'strcat': {     # char *strcat(char *dest, const char *src)
        'dest': 7,
        'src': '6',
    },

    'strcpy': {     # char *strcpy(char *dest, const char *src);
        'dest': 7,
        'src': 6,
    },

    'memcpy': {     # void *memcpy(void *dest, const void *src, size_t n);
        'dest': 7,
        'src': 6,
    }
}

REG = [
    "ax",
    "cx",
    "dx",
    "bx",
    "sp",
    "bp",
    "si",
    "di",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15"
]

reg_number = [
    ('ax', 'eax', 'rax'),
    ('cx', 'eax', 'rax'),
    ('dx', 'edx', 'rdx'),
    ('bx', 'ebx', 'rbx'),
    ('sp', 'esp', 'rsp'),
    ('bp', 'ebp', 'rbp'),
    ('si', 'esi', 'rsi'),
    ('di', 'edi', 'rdi'),
    ('r8'),
    ('r9'),
    ('r10'),
    ('r11'),
    ('r12'),
    ('r13'),
    ('r14'),
    ('r15')
]

arg_reg = [
    7, 6, 2, 1, 8, 9
]

def check_operand_arg(operand):
    return (operand.base in arg_reg) or (operand.index in arg_reg)

def check_operand(op, operand):
    check = 0
    if operand.base != None:
        check |= op.is_reg(operand.base)
    if operand.index != None:
        check |= op.is_reg(operand.index)
    if operand.flag == idaapi.o_imm and op.type == idaapi.o_imm:
        check |= operand.number == op.value
    return check

def hexstr(number):
    return "0x%x" % number


def regt2reg(reg_t):
    for i, reg in enumerate(reg_number):
        if reg_t in reg:
            return i
    return -1


REX_B = 1
REX_X = 2
INDEX_NONE = 4


class FEOperand():
    def __init__(self, base, index=None, scale=0, number=0, flag=idaapi.o_reg):
        self.base = base
        self.index = index
        self.scale = scale
        self.number = number
        self.flag = flag
        self.init_name()

    @classmethod
    def init(cls, inst, index):
        op = inst.Operands[index - 1]
        return cls(
            cls.x86_base(inst, op),
            cls.x86_index(inst, op),
            cls.x86_scale(op),
            op.addr,
            op.type
        )

    def get_reg(self):
        return [self.base, self.index]

    def init_name(self):

        if self.flag == idaapi.o_reg:
            self.name = "%s" % (REG[self.base])
            return

        self.name = "[%s" % (REG[self.base])
        if self.index != None:
            self.name += "+%s" % (REG[self.index])
        if self.scale:
            self.name += "*%d" % (self.scale)
        if self.number:
            self.name += "+%d" % (self.number)
        self.name += "]"

    @classmethod
    def sib_base(cls, inst, op):
        base = op.specflag2 & 7
        if inst.insnpref & REX_B:
            base |= 8
        return base

    @classmethod
    def sib_index(cls, inst, op):
        index = (op.specflag2 >> 3) & 7
        if inst.insnpref & REX_X != 0:
            index |= 8
        return index

    @classmethod
    def sib_scale(cls, op):
        scale = (op.specflag1 >> 6) & 3
        return scale

    @classmethod
    def x86_base(cls, inst, op):
        if op.specflag1:
            if op.type == idaapi.o_mem:
                return None
            return cls.sib_base(inst, op)
        else:
            return op.phrase

    @classmethod
    def x86_index(cls, inst, op):
        if op.specflag1:
            idx = cls.sib_index(inst, op)
            if idx != INDEX_NONE:
                return idx 
            return None
        else:
            return None

    @classmethod
    def x86_scale(cls, op):
        if op.specflag1:
            return cls.sib_scale(op)
        else:
            return 0


# logger
class FELogger():
    """
    日志、调试配置管理类
    """

    enable_dbg = True
    log_path = ''
    log_fd = None
    time_cost = {}

    @classmethod
    def get_dbg_mode(cls):
        return cls.enable_dbg

    @classmethod
    def enable_debug(cls):
        cls.enable_dbg = True

    @classmethod
    def disable_debug(cls):
        cls.enable_dbg = False

    @classmethod
    def reload(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if cls.get_dbg_mode():
                cur_workpath = os.getcwd()
                log_filename = '%s.xdbg' % idaapi.get_root_filename()
                log_filepath = os.path.join(cur_workpath, log_filename)
                cls.log_path = log_filepath
                if cls.log_fd:
                    cls.log_fd = None
                cls.log_fd = open(cls.log_path, 'a')
            return func(*args, **kwargs)
        return wrapper

    @classmethod
    def log_time(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            s_time = time.perf_counter()
            ret_t = func(*args, **kwargs)
            e_time = time.perf_counter()
            if not func.__name__ in cls.time_cost:
                cls.time_cost[func.__name__] = 0
            cls.time_cost[func.__name__] += e_time - s_time
            return ret_t
        return wrapper

    @classmethod
    def show_time_cost(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ret_t = func(*args, **kwargs)
            for func_name in cls.time_cost:
                cls.info('%s: %f seconds' %
                         (func_name, cls.time_cost[func_name]))
            return ret_t
        return wrapper

    @classmethod
    def log(cls, level, msg, debug):
        if level == 'console':
            msg_t = '%s\n' % msg
        else:
            msg_t = '[%s] %s\n' % (level, msg)

        idaapi.msg(msg_t)
        if level == 'warn' or level == 'erro':
            idaapi.warning(msg_t)

    @classmethod
    def console(cls, msg, debug=False):
        cls.log(level='console', msg=msg, debug=debug)

    @classmethod
    def info(cls, msg, debug=False):
        cls.log(level='info', msg=msg, debug=debug)

    @classmethod
    def warn(cls, msg, debug=False):
        cls.log(level='warn', msg=msg, debug=debug)

    @classmethod
    def erro(cls, msg, debug=False):
        cls.log(level='erro', msg=msg, debug=debug)


class FEArgsTracer:

    def __init__(self, addr, reg, max_node=1024) -> None:
        self.init_variable()

        self.addr = addr
        self.reg = reg
        self.max_node = max_node

        self.init_tree()
        self.init_blk_cfg()
        self.init_cache()

    def init_variable(self):
        # __init__
        self.addr = 0
        self.reg = 0
        self.max_node = 1024
        # init_blk_cfg
        self.cfg = []
        self.func = None
        # init_tree
        self.tree = {}
        # init_cache
        self.cache = {}

    def create_tree_node(self, addr, prev=None):
        return {
            "addr": addr,
            "prev": prev,
        }

    def init_tree(self):
        self.tree = self.create_tree_node(self.addr)

    def init_blk_cfg(self):
        f = idaapi.get_func(self.addr)
        if f:
            self.cfg = idaapi.FlowChart(f)
            self.func = f

    def init_cache(self):
        self.cache = {"addr": set(), "all_node": set()}
        for i in range(15):
            self.cache.update({i: set()})

    def get_next_reg(self, addr, operand):
        print("回溯0x%x %s" % (addr, operand.name))
        addr_t = addr
        operand_t = operand

        inst = idautils.DecodeInstruction(addr_t)

        if inst.itype == idaapi.NN_call and addr_t != self.addr:
            FELogger.info("[0x%x]途经函数" % (addr_t))
            FELogger.info("[0x%x]%s" %
                          (addr_t, idc.generate_disasm_line(addr_t, 1)))
            func_addr = inst.Op1.addr
            func_name = idc.print_operand(addr_t, 0)
            func = idaapi.get_func(func_addr)
            if func.does_return():
                if 0 in operand_t.get_reg():
                    FELogger.info("[0x%x]ax寄存器存放返回值，大概率是此处函数调用产生" % (addr_t))
                    FELogger.info("[0x%x]%s" % (
                        addr_t, idc.generate_disasm_line(addr_t, 1)))
                    return None
            if func_name in SOURCE_FUNC:
                if SOURCE_FUNC[func_name]['dest'] in operand_t.get_reg():
                    if SOURCE_FUNC[func_name]['src'] == None:
                        FELogger.info("[0x%x]找到赋值起点，停止回溯[%s]" %
                                      (addr_t, operand_t.name))
                        FELogger.info("[0x%x]%s" % (
                            addr_t, idc.generate_disasm_line(addr_t, 1)))
                        return None
                    else:
                        FELogger.info("[0x%x]传递到下个寄存器, 由[%s]传递到[%s]" % (
                            addr_t, REG[SOURCE_FUNC[func_name]['dest']], REG[inst.Op2.reg]))
                        FELogger.info("[0x%x]%s" % (
                            addr_t, idc.generate_disasm_line(addr_t, 1)))
                        return SOURCE_FUNC[func_name]['src']

        if check_operand(inst.Op1, operand_t):
            if inst.itype == idaapi.NN_mov:

                # 传递
                # mov dest_reg, src_reg;
                if inst.Op2.type == idaapi.o_reg:
                    FELogger.info("[0x%x]传递到下个寄存器, 由[%s]赋值到[%s]" %(addr_t, REG[inst.Op2.reg], REG[inst.Op1.reg]))
                    FELogger.info("[0x%x]%s" % (
                        addr_t, idc.generate_disasm_line(addr_t, 1)))
                    if inst.Op1.is_reg(operand_t.base):
                        operand_t.base = inst.Op2.reg 
                    else:
                        operand_t.index = inst.Op2.reg 
                    operand_t.init_name()
                    return operand_t

                # 停止
                # mov reg, imm;
                if inst.Op2.type == idaapi.o_imm:
                    # FELogger.info("[0x%x]找到赋值起点，停止回溯[%s]被赋值[%d]" %(addr_t, REG[reg_t], inst.Op1.value))
                    FELogger.info("[0x%x]%s" % (
                        addr_t, idc.generate_disasm_line(addr_t, 1)))
                    return None

                # 传播
                # mov reg, [base_reg+index_reg+..];
                if inst.Op2.type in (idaapi.o_phrase, idaapi.o_displ):
                    operand_t = FEOperand.init(inst, 2)
                    FELogger.info("[0x%x]获得传播指令，继续回溯: %s" %
                                  (addr_t, operand_t.name))
                    FELogger.info("[0x%x]%s" % (
                        addr_t, idc.generate_disasm_line(addr_t, 1)))
                    return operand_t

            if inst.itype in (idaapi.NN_test, idaapi.NN_cmp):
                return operand

            # 干扰
            # add reg, ..; 
            FELogger.info("[0x%x]存在对目标寄存器的操作, 停止回溯，尝试手动分析" % (addr_t))
            FELogger.info("[0x%x]%s" %
                          (addr_t, idc.generate_disasm_line(addr_t, 1)))
            return None

        # 无用
        return operand

    def trace_handle(self, addr, operand):
        """
        处理回溯事件
        """
        next_addr = idaapi.prev_head(addr, 0)
        next_operand = self.get_next_reg(addr, operand)

        return (next_addr, next_operand)

    def trace_block(self, blk, node, operand):
        """
        在一个基本块内回溯
        """
        operand_t = operand
        cur_t = node['addr']

        while operand_t != None and cur_t >= blk.start_ea:
            cur_t, operand_t = self.trace_handle(cur_t, operand_t)
            if cur_t == self.func.start_ea:
                FELogger.info("查找到函数起始")
                if check_operand_arg(operand_t):
                    FELogger.info("由函数参数传入: %s" % (operand_t.name))
                operand_t = None 

        return (idaapi.next_head(cur_t, idaapi.BADADDR), operand_t)

    def trace_next(self, blk, node, operand):
        """
        下一轮回溯
        """
        for blk_t in blk.preds():
            addr = idaapi.prev_head(blk_t.end_ea, 1)
            FELogger.info("基本块跳转\t[0x%x]\t[%s]" % (addr, operand.name))
            node_t = self.create_tree_node(addr, node)
            operand_t = copy.copy(operand)
            self.dfs(node_t, operand_t, blk_t)
            FELogger.info("回溯完成\t[0x%x]\t[%s]" % (addr, operand_t.name))

    def get_node_number(self):
        """
        获取已回溯节点数
        """
        return len(self.cache['all_node'])

    def push_cache_node(self, addr, operand):
        """
        将节点地址添加到缓存列表
        """
        if operand.flag == idaapi.o_reg:
            if operand.base in self.cache:
                self.cache['all_node'].add(addr)
                if addr not in self.cache[operand.base]:
                    self.cache[operand.base].add(addr)
                    return True
        else:
            self.cache['all_node'].add(addr)
            if operand.name in self.cache:
                self.cache[operand.name].add(addr)
                return True
            self.cache.update({operand.name: set()})
            self.cache[operand.name].add(addr)
            return True
        return False

    def dfs(self, node, operand, blk):
        """深度优先搜索
        node: 当前节点
        reg: 回溯寄存器
        blk: 当前基本块
        """
        # FELogger.info("开始回溯\t[0x%x]\t[%s]" % (node['addr'], REG[reg]))
        blk_t = blk
        if self.get_node_number() <= self.max_node:
            if self.push_cache_node(node['addr'], operand):
                cur_t, operand_t = self.trace_block(blk_t, node, operand)
                if operand_t != None:
                    self.trace_next(blk_t, node, operand_t)
                else:
                    self.cache['addr'].add(hexstr(cur_t))
            else:
                FELogger.info("该块已经回溯， 跳过")
        else:
            FELogger.info("超出最大回溯块数量")

    def get_blk(self):
        """
        获取addr所在的基本块
        """
        for blk in self.cfg:
            if blk.start_ea <= self.addr and blk.end_ea >= self.addr:
                return blk
        return None

    @FELogger.show_time_cost
    @FELogger.log_time
    def run(self):
        blk = self.get_blk()
        self.dfs(self.tree, FEOperand(self.reg), blk)
        return list(self.cache['addr'])


class FEFuncTestForm(idaapi.Form):

    def __init__(self):
        idaapi.Form.__init__(self, """STARTITEM 0
Functional Test
DFS测试（从某地址回溯某寄存器）：
<##测试:{btn_dfs_test_1}>
DFS测试（从某函数所有调用地址回溯某寄存器）：
<##测试:{btn_dfs_test_2}>
""", {
            'btn_dfs_test_1': idaapi.Form.ButtonInput(self.btn_dfs_test_1),
            'btn_dfs_test_2': idaapi.Form.ButtonInput(self.btn_dfs_test_2)
        })

    def btn_dfs_test_1(self, code=0):
        addr_t = idaapi.ask_str('', 0, '请输入回溯起点地址')
        reg_t = idaapi.ask_str('', 0, '请输入回溯寄存器')
        reg = regt2reg(reg_t)
        if (addr_t and addr_t != '') and (reg != -1):
            try:
                addr_t = int(addr_t, 16)
            except Exception:
                FELogger.warn("无效地址")
                return

            FELogger.info("从地址%s回溯寄存器[%s]" % (hexstr(addr_t), REG[reg]))
            tracer = FEArgsTracer(addr_t, reg, 256)
            source_addr = tracer.run()
            print('source_addr: ', source_addr)
        else:
            FELogger.warn("请输入起点地址和寄存器")

    def btn_dfs_test_2(self, code=0):
        tgt_t = idaapi.ask_str('', 0, '请输入函数名')
        reg_t = idaapi.ask_str('', 0, '请输入回溯寄存器')
        reg = regt2reg(reg_t)
        if (tgt_t and tgt_t != '') and (reg != -1):
            for func_addr_t in idautils.Functions():
                func_name_t = idaapi.get_func_name(func_addr_t)
                if func_name_t == tgt_t:
                    for xref_addr_t in idautils.CodeRefsTo(func_addr_t, 0):
                        if idaapi.get_func(xref_addr_t):
                            FELogger.info("从地址%s回溯寄存器[%s]" % (
                                hexstr(xref_addr_t), REG[reg]))
                            tracer = FEArgsTracer(
                                xref_addr_t, reg, max_node=256)
                            source_addr = tracer.run()
                            print('source_addr: ', source_addr)
                    break
        else:
            FELogger.warn("请输入函数名和寄存器")


if __name__ == '__main__':
    main = FEFuncTestForm()
    main.Compile()
    main.Execute()
