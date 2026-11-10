// Imported comparison ABI summaries. No protocol or target-specific addresses.
// Included after Plan/read_reg/emit_plan; all analysis callbacks hold the taint lock.
#include <elf.h>
struct CompareSlot { ADDRINT address; std::string name; UINT32 image; };
static std::vector<CompareSlot> compare_slots;
static bool copy_app(ADDRINT address, void *value, size_t size) {
    return PIN_SafeCopy(value, reinterpret_cast<void *>(address), size) == size;
}
static bool comparison_name(const std::string &name) {
    return name == "strcmp" || name == "strncmp" || name == "memcmp" || name == "bcmp";
}
static void comparison_image(IMG img, VOID *) {
    // Read the application's ELF dynamic table, independent of debug symbols and IFUNC names.
    Elf64_Ehdr eh{};
    ADDRINT base = IMG_LowAddress(img), bias = IMG_LoadOffset(img);
    if (!copy_app(base, &eh, sizeof eh) || memcmp(eh.e_ident, ELFMAG, SELFMAG) ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_machine != EM_X86_64 ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum > 1024) return;
    ADDRINT dynamic = 0; size_t dynamic_size = 0;
    for (unsigned i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr ph{};
        if (!copy_app(base + eh.e_phoff + i * sizeof ph, &ph, sizeof ph)) return;
        if (ph.p_type == PT_DYNAMIC) { dynamic = bias + ph.p_vaddr; dynamic_size = ph.p_memsz; }
    }
    ADDRINT symtab = 0, strtab = 0, rela = 0, plt = 0;
    size_t relasz = 0, pltsz = 0, strsz = 0; bool rela_plt = false;
    for (size_t i = 0; dynamic && i < std::min<size_t>(dynamic_size / sizeof(Elf64_Dyn), 4096); ++i) {
        Elf64_Dyn d{};
        if (!copy_app(dynamic + i * sizeof d, &d, sizeof d) || d.d_tag == DT_NULL) break;
        // ld.so may have already relocated DT pointers when Pin reports the image.
        ADDRINT ptr = d.d_un.d_ptr;
        if (ptr < base) ptr += bias;
        switch (d.d_tag) {
        case DT_SYMTAB: symtab = ptr; break;
        case DT_STRTAB: strtab = ptr; break;
        case DT_STRSZ: strsz = d.d_un.d_val; break;
        case DT_RELA: rela = ptr; break;
        case DT_RELASZ: relasz = d.d_un.d_val; break;
        case DT_JMPREL: plt = ptr; break;
        case DT_PLTRELSZ: pltsz = d.d_un.d_val; break;
        case DT_PLTREL: rela_plt = d.d_un.d_val == DT_RELA; break;
        default: break;
        }
    }
    if (!symtab || !strtab) return;
    Guard guard(0);
    for (auto table : {std::make_pair(rela, relasz), std::make_pair(plt, rela_plt ? pltsz : size_t(0))}) {
        for (size_t i = 0; table.first && i < std::min<size_t>(table.second / sizeof(Elf64_Rela), 1048576); ++i) {
            Elf64_Rela r{}; Elf64_Sym sym{};
            if (!copy_app(table.first + i * sizeof r, &r, sizeof r)) break;
            auto type = ELF64_R_TYPE(r.r_info);
            if (type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT) continue;
            if (!copy_app(symtab + ELF64_R_SYM(r.r_info) * sizeof sym, &sym, sizeof sym) || sym.st_name >= strsz) continue;
            char name[16] = {};
            size_t n = std::min<size_t>(sizeof name - 1, strsz - sym.st_name);
            if (!copy_app(strtab + sym.st_name, name, n) || !comparison_name(name)) continue;
            compare_slots.push_back({bias + r.r_offset, name, IMG_Id(img)});
        }
    }
}
static void comparison_unload(IMG img, VOID *) {
    Guard guard(0);
    compare_slots.erase(std::remove_if(compare_slots.begin(), compare_slots.end(),
        [&](const CompareSlot &s) { return s.image == IMG_Id(img); }), compare_slots.end());
}
static void comparison_before(Thread &t, THREADID tid, Plan *p, const CONTEXT *ctx, ADDRINT target) {
    if (!ComparisonModels.Value()) return;
    ADDRINT sp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP);
    // Match both continuation PC and stack level; discard frames unwound by longjmp/exceptions.
    while (!t.comparisons.empty() && sp > t.comparisons.back().sp) t.comparisons.pop_back();
    if (!t.comparisons.empty() && t.comparisons.back().ip == p->ip && t.comparisons.back().sp == sp) {
        auto frame = t.comparisons.back(); t.comparisons.pop_back();
        if (frame.tag) {
            if (Strict.Value()) fatal("comparison return requires conservative ABI summary");
            // int return, SysV AMD64: EAX defines the low four bytes; upper RAX is cleared.
            clear_reg(t, LEVEL_BASE::REG_RAX);
            std::fill_n(t.regs[LEVEL_BASE::REG_RAX].begin(), 4, frame.tag);
            definitions(); ++fallback_events;
            fprintf(out, "{\"type\":\"model\",\"seq\":%llu,\"tid\":%u,\"model\":\"comparison_return\","
                         "\"function\":%s,\"policy\":\"conservative\",\"return_tag\":%u,\"return_ip\":%llu,"
                         "\"compared_bytes\":%llu,\"result\":%d,\"basis\":\"imported_symbol_abi_prefix_union\"}\n",
                    (unsigned long long)(events + 1), tid, quote(frame.name).c_str(), frame.tag,
                    (unsigned long long)p->ip, (unsigned long long)frame.bytes,
                    int(PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX)));
            event_count();
        }
    }
    if (!p->control || p->conditional || p->ret) return;
    for (const auto &slot : compare_slots) {
        ADDRINT resolved = 0;
        if (!copy_app(slot.address, &resolved, sizeof resolved) || resolved != target) continue;
        ADDRINT continuation = p->next, resume_sp = sp;
        if (!p->call) { // PLT tail jump: return address was pushed by the caller.
            if (!copy_app(sp, &continuation, sizeof continuation)) return;
            resume_sp += sizeof(ADDRINT);
        }
        if (!t.comparisons.empty() && t.comparisons.back().sp == resume_sp && t.comparisons.back().ip == continuation) return;
        ADDRINT a = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI), b = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI);
        bool strings = slot.name == "strcmp" || slot.name == "strncmp";
        size_t bound = slot.name == "strcmp" ? size_t(-1) : PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX);
        Tag provenance = slot.name == "strcmp" ? 0 : tags.fold(read_reg(t, LEVEL_BASE::REG_RDX), 8);
        size_t used = 0; bool finished = bound == 0;
        for (; used < std::min<size_t>(bound, MaxInput.Value());) {
            unsigned char av = 0, bv = 0;
            if (!copy_app(a + used, &av, 1) || !copy_app(b + used, &bv, 1)) break;
            provenance = tags.join(provenance, tags.join(shadow.get(a + used), shadow.get(b + used)));
            ++used;
            if (av != bv || (strings && (!av || !bv)) || used == bound) { finished = true; break; }
        }
        if (!finished) gap("comparison summary prefix truncated or unreadable");
        if (t.comparisons.size() >= 128) { gap("comparison summary stack limit"); return; }
        t.comparisons.push_back({continuation, resume_sp, provenance, used, slot.name});
        return;
    }
}
