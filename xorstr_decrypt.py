import sys
import ida_allins
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_search
import ida_lines
import ida_ua
import idaapi
import idc

decrypted_strings = []

class DecryptedStringsChooser(ida_kernwin.Choose):
    def __init__(self):
        title = "Decrypted Strings"
        columns = [
            ["Address", 10 | ida_kernwin.Choose.CHCOL_HEX],
            ["Disassembly", 120 | ida_kernwin.Choose.CHCOL_PLAIN],
        ]
        ida_kernwin.Choose.__init__(self, title, columns, ida_kernwin.Choose.CH_MODAL)

    def OnGetSize(self):
        return len(decrypted_strings)

    def OnGetLine(self, n):
        return [hex(decrypted_strings[n][0]), decrypted_strings[n][1]]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(decrypted_strings[n][0])
        return False


class xor_decryption_mod(ida_idaapi.plugmod_t):
    stack_count = 0

    def __del__(self):
        ida_kernwin.msg("Unloaded xor decryptor!\n")

    def show_decrypted_strings_table(self):
        if decrypted_strings:
            chooser = DecryptedStringsChooser()
            chooser.Show()
        else:
            ida_kernwin.warning("No decrypted strings found!")

    """Store decrypted string with address"""

    def add_decrypted_string(self, address):
        disasm = self.get_disasam(address)
        decrypted_strings.append((address, disasm))

    """
    Returns the instruction at a linear address
    """

    def get_insn(self, ea: int):
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        return insn

    """
    Returns the previous instruction
    """

    def get_previous_insn(self, ea):
        insn = idaapi.insn_t()
        idaapi.decode_prev_insn(insn, ea)
        return insn

    """
    Returns the next instruction, or None if it can't find any
    """

    def get_next_insn(self, previous_insn):
        insn = idaapi.insn_t()
        if previous_insn.size == 0:
            return None
        idaapi.decode_insn(insn, previous_insn.ea + previous_insn.size)
        return insn

    """Retrieve formatted disassembly for an address."""

    def get_disasam(self, address):
        mnemonic = idaapi.print_insn_mnem(address)
        if not mnemonic:
            return "Unknown"

        full_disasm = idc.GetDisasm(address)
        return full_disasm if full_disasm else mnemonic

    """
    Finds where the initial mov is for the key or data. This matches the stack address and checks that it is being written to with a mov.
    This moves backwards.
    returns the instruction where the first mov is for the data or key.

    movabs rax, -4762152789334367252
    >> RETURN HERE FOR DATA << mov QWORD PTR [rsp], rax
    movabs rax, -6534519754492314190
    mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    >> RETURN HERE FOR KEY << mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    vmovdqa YMMWORD PTR [rsp], ymm0
    """

    def find_stack_push_start(self, insn, stackaddr, max_iterations=5000):
        iterations = 0
        while iterations < max_iterations:
            if insn is None or insn.ea == idaapi.SIZE_MAX:
                return None

            # Check if this instruction writes a register to our target stack address
            is_target_mov = (
                insn.itype == ida_allins.NN_mov
                and insn.ops[0].type == ida_ua.o_displ
                and insn.ops[0].addr == stackaddr
                and insn.ops[1].type == ida_ua.o_reg
            )

            if is_target_mov:
                return insn

            insn = self.get_previous_insn(insn.ea)
            iterations += 1

        return None

    """
    Finds the last findable immediate value for known for a register by moving backwards until finding a mov instruction where the register is written to
    This moves backwards.
    returns the immediate value of a register

    movabs rax, >> RETURNS THIS: -6534519754492314190 <<
    mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    vmovdqa YMMWORD PTR [rsp], ymm0
    """

    def find_register_value(self, insn, reg, max_iterations=4096):
        original_insn = insn

        iterations = 0
        while iterations < max_iterations:
            if insn is None or insn.ea == idaapi.SIZE_MAX:
                print(
                    f"[DEBUG] exceeded iterations for register {reg:08X} at {original_insn.ea:08X} {self.get_disasam(original_insn.ea)}"
                )
                return None

            is_mov_to_reg = (
                insn.itype == ida_allins.NN_mov
                and insn.ops[0].type == ida_ua.o_reg
                and insn.ops[0].reg == reg
            )

            if is_mov_to_reg:
                break

            insn = self.get_previous_insn(insn.ea)
            iterations += 1

        if iterations >= max_iterations:
            print(
                f"[DEBUG] no candidate found for register {reg:08X} at {original_insn.ea:08X} {self.get_disasam(original_insn.ea)}"
            )
            return None

        if insn.ops[1].type == ida_ua.o_imm:
            # print(f"[DEBUG] found cadidate for register {reg:08X} at {insn.ea:08X} {self.get_disasam(insn.ea)}")
            return insn.ops[1].value

        stack_insn = self.find_stack_push_start(
            self.get_previous_insn(insn.ea), insn.ops[1].addr
        )

        if stack_insn is None:
            print(
                f"[DEBUG] no stack push candidate found for register {reg:08X} at {insn.ea:08X} {self.get_disasam(insn.ea)}"
            )
            return None

        return self.find_register_value(stack_insn, stack_insn.ops[1].reg)

    """
    Used to find what stack address is moved into the xmm/ymm register later used in the pxor instructions
    This moves backwards.
    returns the movdqx instruction

    movabs rax, -6534519754492314190
    mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    RETURN HERE >> vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    vmovdqa YMMWORD PTR [rsp], ymm0
    """

    def find_register_movdq_insn(self, insn, reg, max_iterations=1024):
        movdq_instructions = [
            ida_allins.NN_vmovdqa,
            ida_allins.NN_vmovdqu,
            ida_allins.NN_movdqa,
            ida_allins.NN_movdqu,
        ]

        iterations = 0
        while iterations < max_iterations:
            if insn is None or insn.ea == idaapi.SIZE_MAX:
                return None

            is_movdq = insn.itype in movdq_instructions
            is_target_reg = insn.ops[0].type == ida_ua.o_reg and insn.ops[0].reg == reg

            if is_movdq and is_target_reg:
                return insn

            insn = self.get_previous_insn(insn.ea)
            iterations += 1

        return None

    """
    Used to find where the ymm/xmm xored output is moved back onto the stack (useful to find where to place psuedocode comments)
    This moves forwards
    returns the movdqx instruction where this happens

    movabs rax, -6534519754492314190
    mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
     >> RETURNS HERE << vmovdqa YMMWORD PTR [rsp], ymm0
    """

    def find_stack_movdq_insn(self, insn, reg, max_iterations=1000):
        movdq_instructions = [
            ida_allins.NN_vmovdqa,
            ida_allins.NN_vmovdqu,
            ida_allins.NN_movdqa,
            ida_allins.NN_movdqu,
        ]

        iterations = 0
        while iterations < max_iterations:
            if insn is None or insn.ea == idaapi.SIZE_MAX:
                return None

            is_movdq = insn.itype in movdq_instructions
            is_target_reg = insn.ops[1].type == ida_ua.o_reg and insn.ops[1].reg == reg

            if is_movdq and is_target_reg:
                return insn

            insn = self.get_next_insn(insn)
            iterations += 1

        return None

    """
    Finds the next stack push instruction which matches the stack address given.
    This moves forwards
    returns the mov instruction which accesses the address

    movabs rax, -6534519754492314190
    >> CALLED HERE << mov QWORD PTR [rsp+8], rax
    movabs rax, -2862143164529545214
    >> RETURNS HERE << mov QWORD PTR [rsp+16], rax
    movabs rax, -4140208776682645948
    mov QWORD PTR [rsp+24], rax
    vmovdqa ymm1, YMMWORD PTR [rsp]
    movabs rax, -2550414817236710003
    mov QWORD PTR [rsp+32], rax
    movabs rax, -4595755740016602734
    mov QWORD PTR [rsp+40], rax
    movabs rax, -5461194525092864914
    mov QWORD PTR [rsp+48], rax
    movabs rax, -4140208776682645984
    mov QWORD PTR [rsp+56], rax
    vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    vmovdqa YMMWORD PTR [rsp], ymm0
    """

    def find_next_stack_push(
        self, insn, address, search_backwards=True, max_iterations=5000
    ):
        original_insn = insn

        if search_backwards:
            # print(f"[DEBUG] starting backward search from {original_insn.ea:08X}")
        
            iterations = 0
            while iterations < max_iterations:    
                if insn is None or insn.ea == idaapi.SIZE_MAX:
                    break

                if insn.itype == ida_allins.NN_mov and insn.ops[0].addr == address:
                #   print(f"[DEBUG] found backward stack push address {address:08X}")
                    return insn

                insn = self.get_previous_insn(insn.ea)
                iterations += 1
        
        # search forward
        insn = original_insn
        iterations = 0
        while iterations < max_iterations:
            if insn is None or insn.ea == idaapi.SIZE_MAX:
                print(f"[DEBUG] exceeded stack push iterations try for {address:08X} at {original_insn.ea:08X}")
                return None

            if insn.itype == ida_allins.NN_mov and insn.ops[0].addr == address:
                #print(
                #    f"[DEBUG] found forward next stack push address {address:08X} at {insn.ea:08X} {self.get_disasam(insn.ea)}"
                #)
                return insn

            insn = self.get_next_insn(insn)
            iterations += 1
            
        print(f"[DEBUG] no iterations found for stack push for {address:08X} at {original_insn.ea:08X}")

        return None

    """
    Handles a basic xor cipher with two byte arrays
    """

    def byte_xor(self, ba1, ba2):
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    """
    Handles the string decryption.
    Steps:
    Find where it starts pushing data onto the stack
    Figure if we're dealing with xmm/ymm registers
    Find immediate values of the data and append them to a byte array
    Find where it starts pushing the key onto the stack
    Find immediate values of the key and append them to a byte array
    Xor the two arrays, then set comments as necessary
    """

    def handle_str_decryption(self, data_reg, key_address, func_addr, pxor_insn):
        previous_insn = self.find_register_movdq_insn(pxor_insn, data_reg)
        if previous_insn == None:
            return None

        data_address = previous_insn.ops[1].addr

        # print(f"[DEBUG] found movdq inst for {data_reg:08X} at {previous_insn.ea:08X} {self.get_disasam(previous_insn.ea)}")

        mov_start = self.find_stack_push_start(previous_insn, data_address)
        if mov_start == None:
            return None
        if idaapi.get_reg_name(data_reg, 16).startswith("xmm"):
            expected_pushes = 2
        elif idaapi.get_reg_name(data_reg, 16).startswith("ymm"):
            expected_pushes = 4
        else:
            return None

        # print(f"[DEBUG] found initial stack push start for {data_address:08X} at {mov_start.ea:08X} {self.get_disasam(mov_start.ea)}")

        xor_data = bytes()
        xor_key = bytes()

        mov_insn = mov_start
        for x in range(0, expected_pushes):
            register_val = self.find_register_value(
                mov_insn, mov_insn.ops[1].reg, 4096 * 10
            )
            if register_val is None:
                print(
                    f"[DEBUG] failed to find register value {mov_insn.ops[1].reg:08X} at {mov_insn.ea:08X} {self.get_disasam(mov_insn.ea)}"
                )
                return None

            xor_data += register_val.to_bytes(8, sys.byteorder)

            if x != expected_pushes - 1:
                #mov_insn = self.find_next_stack_push(
                #    mov_insn, data_address + (x + 1) * stack_increment, True
                #)
                
                # Try forward (+8)
                next_push = self.find_next_stack_push(mov_insn, data_address + (x + 1) * 8)

                if next_push is None:
                    # If forward fails, try backward (-8)
                    next_push = self.find_next_stack_push(mov_insn, data_address - (x + 1) * 8)

                if next_push is None:
                    print(
                        f"[DEBUG] failed to find next stack push value {register_val:08X} mov_start = {mov_start.ea:08X}"
                    )
                    return None

                mov_insn = next_push

            if mov_insn == None:
                #print(
                #    f"[DEBUG] failed to find next stack push value {register_val:08X} mov_start = {mov_start.ea:08X}"
                #)
                return None

        mov_insn = self.find_stack_push_start(previous_insn, key_address)
        if mov_insn == None:
            fail_key_addr = key_address
            mov_insn = None
            for offset in range(-128, 128, 8):
                candidate_address = key_address + offset
                mov_insn = self.find_stack_push_start(previous_insn, candidate_address)
                if mov_insn is not None:
                    # print(
                    #    f"---> first try: {fail_key_addr:08X} but success in {candidate_address:08X}"
                    # )
                    break
            if mov_insn is None:
                print(
                    f"[DEBUG] failed to find stack push start at {previous_insn.ea:08X} {self.get_disasam(previous_insn.ea)}"
                )
                return None

        # print(f"[DEBUG] found second stack push start for {key_address:08X} at {mov_start.ea:08X} {self.get_disasam(mov_start.ea)}")

        for x in range(0, expected_pushes):
            register_val = self.find_register_value(
                mov_insn, mov_insn.ops[1].reg, 4096 * 10
            )
            if register_val == None:
                print(
                    f"[DEBUG] failed to find register value {mov_insn.ops[1].reg:08X} in expected pushes at {mov_insn.ea:08X} {self.get_disasam(mov_insn.ea)}"
                )
                return None

            xor_key += register_val.to_bytes(8, sys.byteorder)

            if x != expected_pushes - 1:
                mov_insn = self.find_next_stack_push(
                    mov_insn, key_address + (x + 1) * 8
                )
            if mov_insn == None:
                print(f"[DEBUG] failed to find next stack push in expected pushes!")
                return None

        # print(f"[DEBUG] found register value {register_val:08X} at {mov_start.ea:08X} {self.get_disasam(mov_start.ea)}")

        decrypted = self.byte_xor(xor_data, xor_key)
        encoding, result = self.detect_encoding_and_decode(decrypted)
        comment = f"Decrypted {encoding}: {result}"
        idc.set_cmt(func_addr, comment, 0)
        self.add_decrypted_string(func_addr)

        # print(f"[DEBUG] {func_addr:08X} decrypt success!")

        mov_to_stack_insn = self.find_stack_movdq_insn(pxor_insn, pxor_insn.ops[0].reg)
        cfunc = idaapi.decompile(mov_to_stack_insn.ea)
        if cfunc:
            tl = idaapi.treeloc_t()
            tl.ea = mov_to_stack_insn.ea
            tl.itp = idaapi.ITP_SEMI
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()
        return result

    """
    Determines whether the decrypted data is a UTF-8 or UTF-16-LE encoded string.
    """

    def detect_encoding_and_decode(self, decrypted):
        try:
            result = decrypted.decode("utf-8").rstrip("\x00")

            # Check if it contains mostly printable characters
            if all(0x20 <= ord(c) <= 0x7E for c in result):
                return "UTF-8", result

        except UnicodeDecodeError:
            pass

        # Check for potential UTF-16 characteristics
        if len(decrypted) >= 2 and all(
            decrypted[i] == 0 for i in range(1, len(decrypted), 2)
        ):
            try:
                result = decrypted.decode("utf-16-le").rstrip("\x00")
                return "UTF-16", result
            except UnicodeDecodeError:
                pass

        # If both decoding attempts fail, return hex representation
        result = " ".join(["{:02x}".format(b) for b in decrypted])
        return "Raw (unprintable)", result

    """
    Starts the routine for a PXOR instruction
    ex : pxor xmm0, [rbp+1F30h+var_1B90]
    """

    def handle_pxor(self, func_addr, insn):
        data_reg = insn.ops[0].reg
        key_address = insn.ops[1].addr
        return self.handle_str_decryption(data_reg, key_address, func_addr, insn)

    """
    Starts the routine for a VPXOR instruction
    ex : vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
    """

    def handle_vpxor(self, func_addr, insn):
        data_reg = insn.ops[1].reg
        key_address = insn.ops[2].addr
        return self.handle_str_decryption(data_reg, key_address, func_addr, insn)

    """
    Determines if this PXOR instruction matches our target patterns
    """

    def is_target_pxor_instruction(self, insn):
        return insn.itype == ida_allins.NN_pxor

    """
    Determines if this VPXOR instruction matches our target patterns
    """

    def is_target_vpxor_instruction(self, insn):
        return insn.itype == ida_allins.NN_vpxor

    """
    Determines if this XORPS instruction matches our target patterns
    """

    def is_target_xorps_instruction(self, insn):

        if insn.itype != ida_allins.NN_xorps:
            return False

        if insn.ops[0].type != idaapi.o_reg:
            return False

        reg_name = idaapi.get_reg_name(insn.ops[0].reg, insn.ops[0].dtype)
        if not reg_name.startswith("xmm"):
            return False

        if insn.ops[1].type != ida_ua.o_mem and insn.ops[1].type != ida_ua.o_displ:
            return False

        return True

    """
    Starts plugin logic
    """

    def run(self, arg):

        result = idaapi.ask_yn(
            1,
            "Do you wanna run Xorstr decryptor?",
        )

        if result == 1:
            start_ea = idc.get_inf_attr(idc.INF_MIN_EA)
            end_ea = idc.get_inf_attr(idc.INF_MAX_EA)

            match_count = 0

            current_ea = start_ea
            while current_ea < end_ea:
                insn = self.get_insn(current_ea)
                if idaapi.decode_insn(insn, current_ea) > 0:
                    if self.is_target_pxor_instruction(insn):
                        result = self.handle_pxor(current_ea, insn)
                        if result is not None:
                            # print(f"Found match at {current_ea:08X} {result}")
                            match_count += 1
                        else:
                            print(
                                f"Failed PXOR ea: {current_ea:08X} disasam: {self.get_disasam(current_ea)}"
                            )

                    if self.is_target_vpxor_instruction(insn):
                        result = self.handle_vpxor(current_ea, insn)
                        if result is not None:
                            # print(f"Found match at {current_ea:08X} {result}")
                            match_count += 1
                        else:
                            print(
                                f"Failed VPXOR ea: {current_ea:08X} disasam: {self.get_disasam(current_ea)}"
                            )

                    if self.is_target_xorps_instruction(insn):
                        result = self.handle_pxor(  # xorps is handled the same as pxor
                            current_ea, insn
                        )
                        if result is not None:
                            # print(f"Found match at {current_ea:08X} {result}")
                            match_count += 1
                        else:
                            print(
                                f"Failed XORPS ea: {current_ea:08X} disasam: {self.get_disasam(current_ea)}"
                            )

                    current_ea += insn.size
                else:
                    current_ea += 1

            if match_count == 0:
                print("No matching xor instructions found.")
            else:
                print(f"Found {match_count} matching xor instructions!")

            self.show_decrypted_strings_table()

        return 0


class xor_decryption_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Attempts to detect & decrypt JM Xorstring"
    help = ""
    wanted_name = "Xorstring Decryptor"
    wanted_hotkey = "Alt-F8"

    def init(self):
        return xor_decryption_mod()

    def run(self, arg):
        return 0

    def term(self):
        pass


def PLUGIN_ENTRY():
    return xor_decryption_t()
