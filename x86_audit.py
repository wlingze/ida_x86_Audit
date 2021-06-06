import idc 
import idautils 
import idaapi
from prettytable import PrettyTable 


arg_reg = [
	'rdi', 
	'rsi', 
	'rdx', 
	'rcx', 
	'r8', 
	'r9'
]


# set function_name
dangerous_functions = [
    "strcpy", 
    "strcat",  
    "sprintf",
    "read", 
    "getenv"    
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf", 
    "strncat", 
    "snprintf",
    "vprintf", 
    "printf"
]

command_execution_function = [
    "system", 
    "execve",
    "popen",
    "unlink"
]


# describe arg num of function

one_arg_function = (
    "getenv",
    "system",
    "unlink"
)

two_arg_function = (
    "strcpy", 
    "strcat",
    "popen"
)

three_arg_function = (
    "strncpy",
    "strncat", 
    "memcpy",
    "execve",
    "read"
)

format_function_offset_dict = {
    "sprintf":1,
    "sscanf":1,
    "snprintf":2,
    "vprintf":0,
    "printf":0
}

arg_num = [
    one_arg_function,
    two_arg_function,
    three_arg_function,
]






# 当前函数的栈空间大小
def stack_buf(addr):
	return [hex(idc.get_func_attr(addr, idc.FUNCATTR_FRSIZE))]

# 找到函数以后会打印信息
def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Aduiting " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

# 查找函数
def getFuncAddr(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr != idc.BADADDR:
        print(printFunc(func_name))
        return func_addr
    return False

# 从地址提取出参数来，这里考虑了下如果有参数是寄存器传来传去，会进入个简单的回溯函数
def find_arg(arg_addr):
	# 参数不是寄存器的话
	if(idc.get_operand_type(arg_addr, 1) != 1):
		arg = idc.print_operand(arg_addr, 1)
		# 获取参数，如果有offset的话，去掉
		if "offset" in arg:
			return arg[7:]
		else:
			return arg
	# 参数是寄存器的话 (如mov rdi, rax;)， 在此函数内搜索，
	func = idaapi.get_func(arg_addr).start_ea
	line = arg_addr
	return hand_register(arg_addr, idaapi.get_func(arg_addr).start_ea, idc.print_operand(arg_addr, 1))
	
# 获取对应参数位置，一般的函数直接可以通过get_arg_addrs获取对应参数处理的地址，
def enum_arg(call_addr):
	idc.set_color(call_addr,CIC_ITEM,0x00ff00)
	arg = []
	for arg_addr in idaapi.get_arg_addrs(call_addr):
		idc.set_cmt(arg_addr, "addr: 0x%x" % (call_addr), 0)
		idc.set_color(arg_addr,CIC_ITEM,0x00fff0)
		arg.append(find_arg(arg_addr))
	return arg

# 取函数对应参数的个数，这里用了个小技巧让代码更好看了点
def function_arg_number(func_name):
	for i , function in enumerate(arg_num, 1):
		if func_name in function:
			return i 

# 获取全部的cfg
def set_cfg(line):
	f = idaapi.get_func(line)
	if f:
		cfg = idaapi.FlowChart(f)
	else:
		cfg = []
	return cfg

# 获取当前的block
def find_current_block(cfg, line):
	for i  in cfg:
		if i.start_ea <= line and i.end_ea >= line:
			return i 

# 在一个block中处理
def hand_block_inside(line, start, reg_target):
	out = ""
	current = line 
	while(current >= start):
		if (reg_target in [idc.print_operand(current, 1), idc.print_operand(current, 0)]):
			out += '\t0x%x: %s\n' %(current, idc.generate_disasm_line(current, 1))
		current = prev_head(current)
	return out


def hand_block(line, current, reg_target):
	out = ''
	out += "hand_block trace: 0x%x to %s\n" % (line, reg_target)

	cfg = set_cfg(line)
	out += "Get control flow\n"
	
	block = find_current_block(cfg, line)
	out += "Get the current basic block\n"

	out += hand_block_inside(line, block.start_ea, reg_target)

	block_pred = block.preds()
	for i in range(4):
		out += "==== " + "preds " * (i+1) + '\n'
		for pred in block_pred:
			out += 'block pred: 0x%x -- 0x%x\n' % (pred.start_ea, pred.end_ea)
			out += hand_block_inside(pred.end_ea, pred.start_ea, reg_target)

	print(out)
	return idc.print_operand(line, 1) + " => Backtracking"



# 处理寄存器, 从line向上遍历，到satrt_ea返回， 找到第一次对reg_target的操作，返回，
def hand_register(line, start_ea, reg_target):
	current = line 
	while(current >= start_ea):
		current = idc.prev_head(current)
		if(idc.print_insn_mnem(current) == 'jmp'):
			return hand_block(line, current, reg_target)
		if(idc.print_operand(current, 0) == reg_target) and (idc.print_insn_mnem(current) in ['mov', 'lea']):
			return idc.print_operand(current, 1)

# 格式化字符串中指定的参数的处理
def format_args(call_addr, fmt_num, index):
	func = idaapi.get_func(call_addr)
	start = func.start_ea
	string = ""
	# 这里i是指对应在整个调用中的参数的位置，
	# !! 从1开始因为测试的时候考虑printf第一个格式化字符串，后面的就是后推一个, 
	# !! 应该snprintf参数解析错误的bug就是这里， 应该..1改成format_function_offset_dict[func_name]就好了
	for i in range(index+1, fmt_num+index+1):
		# 只查寄存器传递的，push传递的还没考虑，
		if(i >= 6):
			break;
		# 从调用位置向上遍历查找对应的传参寄存器
		line = call_addr
		reg = arg_reg[i]
		while line >= start:
			line = prev_head(line)
			line_arg = idc.print_operand(line, 0)
			# !! 只比较寄存器存在bug (add rdi, 0x10)， 可能被认为是0x10是参数，
			if reg == line_arg:
				idc.set_color(line,CIC_ITEM,0x00fff0)
				# 如果是寄存器传寄存器(mov rdi, rax;)， 调用函数尝试回溯rax，
				if(idc.get_operand_type(line, 1) != 1) and (idc.print_insn_mnem(line) in ['mov', 'lea']):
					string += ", '%s'" %(idc.print_operand(line, 1))
				else:
					string += ", '%s'" % (hand_register(line, start, idc.print_operand(line, 1)))
				break
	return string

# 格式化字符串的函数，进行处理
def format_string(call_addr, format_name, index):
	string = ''
	# 获取对应的格式化字符串
	format_addr = idc.LocByName(format_name)
	# 判断对应地址是否为一个字符串
	if idc.GetStringType(format_addr) == 0:
		fmt_str = idc.GetString(format_addr).decode()

		# 如果有回车，不要换行，打印`\n`字符
		string = "'%s'" % fmt_str.replace('\n', '\\n')

		# 格式化字符串对应%对应的参数
		fmt_num = fmt_str.count('%')
		if fmt_num > 0:
			string += ", %d" % fmt_num
			string += "%s" % format_args(call_addr, fmt_num, index)
	
	# 不是字符串可能存在格式化字符串漏洞
	else:
		string += "null! A dangerous address, may have a format string vulnerability"
	return [string]

# 格式化字符串类函数，枚举参数
def enum_arg_format(call_addr, index):
	# 先常规枚举参数
	arg = enum_arg(call_addr) 
	# 然后单独解析格式化字符串 %会带的参数
	return arg + format_string(call_addr, arg[index], index)

# 审计格式化字符串类函数
def audit_format_function(func_name, func_addr):
	index = format_function_offset_dict[func_name]
	table_head = ['address'] + ["arg%s" %(i+1) for i in range(index + 1)] + [" format&value[string_addr, num of '%', fmt_arg...]"] + ['stack_buf_size']
	table = PrettyTable(table_head)
	# 直接交叉引用，
	for call_addr in idautils.CodeRefsTo(func_addr, 0):
		# 每次处理一个函数调用位置，写入一行内
		table.add_row([hex(call_addr)] + enum_arg_format(call_addr, index)+ stack_buf(call_addr))
	print(table)

# 审计普通函数
def audit_function(func_name, func_addr):
	table_head = ["func_name", "address"] + ["arg%s" % (i+1)  for i in range(function_arg_number(func_name))] + ['stack_buf_size']
	table = PrettyTable(table_head)

	# 直接交叉引用，
	for call_addr in idautils.CodeRefsTo(func_addr, 0):
		# 每次处理一个函数调用位置，写入一行内
		table.add_row([func_name, hex(call_addr)] + enum_arg(call_addr) + stack_buf(call_addr))
	print(table)

# 审计入口函数
def audit(func_name):

	# 先尝试获取函数
	func_addr = getFuncAddr(func_name)
	if func_addr == False:
		return  False

	# 如果获取到了got表位置，尝试解引用到plt表
	if idc.SegName(func_addr) == 'extern':
		func_addr = list(idautils.CodeRefsTo(func_addr, 0))[0]

	# 判断普通函数或者格式化字符串类函数，进入不同函数
	if func_name in format_function_offset_dict:
		return audit_format_function(func_name, func_addr)
	return audit_function(func_name, func_addr)


# 遍历对应的函数类型
def ida_audit():
	start = '''
	'''
	print(start)

	print ("Auditing dangerous functions ......")
	for func_name in dangerous_functions:
		audit(func_name)

	print ("Auditing attention function ......")
	for func_name in attention_function:
		audit(func_name)

	print ("Auditing command execution function ......")
	for func_name in command_execution_function:
		audit(func_name)

	print ("Finished! Enjoy the result ~")

# 入口位置
# ida_audit()
audit("unlink")

